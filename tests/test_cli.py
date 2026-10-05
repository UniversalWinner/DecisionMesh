import io
import json
import os
from types import SimpleNamespace

import pytest

import decision_mesh.runtime_control as control
from decision_mesh import cli
from decision_mesh.capture import atomic_write_owner_only, ensure_spool_dir, owner_file_lock
from decision_mesh.runtime_control import RuntimeErrorCode, RuntimeMetadata, RuntimePaths


def invoke(args, data=""):
    stdout, stderr = io.StringIO(), io.StringIO()
    result = cli.main(args, stdin=io.StringIO(data), stdout=stdout, stderr=stderr)
    return result, stdout.getvalue(), stderr.getvalue()


def test_enroll_and_producer_stdin_acceptance_never_starts_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Runtime", lambda *_args: pytest.fail("runtime must not start"))
    root = tmp_path / "data"
    assert invoke(["producer", "enroll", "--data-dir", str(root)])[0] == 0
    doc = {"source_request_id": "a", "snapshot": {"kind": "question", "title": "A", "summary": "B"}}
    for method in ("create", "update", "resolve", "withdraw"):
        code, output, errors = invoke(
            ["producer", method, "--data-dir", str(root)], json.dumps(doc)
        )
        assert code == 0 and not errors
        receipt = json.loads(output)
        assert receipt["accepted_to_spool"] and receipt["ingested"] is False
    assert not (root / "runtime.json").exists()
    assert not (root / "decisionmesh.db").exists()


@pytest.mark.parametrize(
    "raw",
    ['{"secret":"PRIVATE_TOKEN"}', '{"x":1,"x":2}', "[]", '"' + "a" * (256 * 1024) + '"'],
    ids=["schema", "duplicate", "array", "oversized"],
)
def test_invalid_documents_are_bounded_redacted_and_do_not_start(tmp_path, raw):
    code, output, errors = invoke(["producer", "create", "--data-dir", str(tmp_path / "data")], raw)
    assert code == 1 and not output
    assert "PRIVATE_TOKEN" not in errors and len(errors) < 400
    assert not (tmp_path / "data").exists()


def test_unknown_argv_and_relative_paths_are_redacted():
    code, output, errors = invoke(["setup", "--token", "PRIVATE_TOKEN"])
    assert code == 1 and not output and "PRIVATE_TOKEN" not in errors
    assert invoke(["open", "--data-dir", "relative"])[0] == 1


def test_free_lock_stale_foreign_listener_is_never_contacted(tmp_path, monkeypatch):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    metadata = RuntimeMetadata(instance_id="a" * 32, port=9999, control_secret="c" * 64)
    atomic_write_owner_only(paths.metadata, metadata.model_dump_json().encode())
    monkeypatch.setattr(
        control, "_post", lambda *args, **kwargs: pytest.fail("stale port contacted")
    )
    launched = []

    def launch(*args, **kwargs):
        launched.append(True)
        assert not paths.metadata.exists()
        raise RuntimeErrorCode("installed_command_unavailable")

    with pytest.raises(RuntimeErrorCode):
        control.open_inbox(paths, browser=lambda _: pytest.fail("browser opened"), launcher=launch)
    assert launched


def test_mismatched_hmac_never_opens_browser(tmp_path, monkeypatch):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    metadata = RuntimeMetadata(instance_id="a" * 32, port=9999, control_secret="c" * 64)
    atomic_write_owner_only(paths.metadata, metadata.model_dump_json().encode())
    calls = []

    def post(port, path, payload, **kwargs):
        calls.append(payload)
        if path.endswith("challenge"):
            return {
                "instance_id": metadata.instance_id,
                "challenge": payload["client_nonce"] + "." + control.new_client_nonce(),
            }
        return {
            "operation": "open",
            "instance_id": metadata.instance_id,
            "challenge": payload["challenge"],
            "nonce": control.new_client_nonce(),
            "result": "ok",
            "mac": "0" * 64,
        }

    monkeypatch.setattr(control, "_post", post)
    with owner_file_lock(paths.lock, timeout=0), pytest.raises(RuntimeErrorCode):
        control.open_inbox(paths, browser=lambda _: pytest.fail("browser opened"))
    assert len(calls) == 2
    assert metadata.control_secret not in json.dumps(calls)


def test_readiness_is_bounded_and_opens_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(control, "READINESS_TIMEOUT", 0.1)
    with pytest.raises(RuntimeErrorCode, match="timeout"):
        control.open_inbox(
            RuntimePaths(tmp_path / "data"),
            launcher=lambda *args, **kwargs: None,
            browser=lambda _: pytest.fail("browser opened"),
        )


def test_hidden_launch_uses_installed_command_no_source_fallback(tmp_path, monkeypatch):
    executable = tmp_path / "decisionmesh.exe"
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(control, "resolve_installed_console", lambda: executable)
    calls = []
    monkeypatch.setattr(
        control.subprocess, "Popen", lambda args, **kwargs: calls.append((args, kwargs))
    )
    control.launch_hidden(RuntimePaths(tmp_path / "data"), local_only=True)
    args, options = calls[0]
    assert args == [str(executable), "run", "--data-dir", str(tmp_path / "data"), "--local-only"]
    assert options["stdout"] == control.subprocess.DEVNULL
    if os.name == "nt":
        assert options["creationflags"] & control.subprocess.CREATE_NO_WINDOW
        assert options["startupinfo"].wShowWindow == 0

    def missing():
        raise RuntimeErrorCode("installed_command_unavailable")

    monkeypatch.setattr(control, "resolve_installed_console", missing)
    with pytest.raises(RuntimeErrorCode):
        control.launch_hidden(RuntimePaths(tmp_path / "data"))


def test_short_reference_validation_precedes_browser_or_launch(tmp_path):
    with pytest.raises(RuntimeErrorCode):
        control.open_inbox(
            RuntimePaths(tmp_path / "data"),
            reference="https://bad.test",
            launcher=lambda *args: pytest.fail("launched"),
        )


def test_backup_restore_require_stopped_runtime_and_new_target(tmp_path):
    root = tmp_path / "data"
    with cli.SQLiteStore(root / "decisionmesh.db"):
        pass
    backups = ensure_spool_dir(tmp_path / "backups")
    backup = backups / "backup.db"
    args = ["backup", "--data-dir", str(root), "--destination", str(backup)]
    with owner_file_lock(root / "runtime.lock", timeout=0):
        assert invoke(args)[0] == 1
    assert invoke(args)[0] == 0
    assert invoke(args)[0] == 1
    restored = tmp_path / "restored"
    result = invoke(["restore", "--data-dir", str(restored), "--backup", str(backup)])
    assert result[0] == 0 and "notifications_disabled" in result[1]
    with cli.SQLiteStore(restored / "decisionmesh.db") as store:
        assert not store.get_settings().channel_active
        assert store.recovery_state().restored_at is not None


def test_slow_loopback_response_has_total_time_bound(monkeypatch):
    import socket
    import threading
    import time

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stopped = threading.Event()

    def slow():
        connection, _ = listener.accept()
        try:
            connection.recv(4096)
            for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n":
                if stopped.wait(0.02):
                    break
                try:
                    connection.sendall(bytes([byte]))
                except OSError:
                    break
        finally:
            connection.close()

    thread = threading.Thread(target=slow)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeErrorCode):
            control._post(listener.getsockname()[1], "/control/challenge", {}, timeout=0.15)
        assert time.monotonic() - started < 0.8
    finally:
        stopped.set()
        listener.close()
        thread.join(2)


def test_already_starting_runtime_is_waited_for_without_duplicate_launch(tmp_path, monkeypatch):
    calls = []
    metadata = RuntimeMetadata(instance_id="a" * 32, port=1234, control_secret="c" * 64)

    def active(_paths):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeErrorCode("runtime_starting")
        return metadata

    monkeypatch.setattr(control, "active_metadata", active)
    monkeypatch.setattr(
        control, "authenticate", lambda *args, **kwargs: SimpleNamespace(nonce="safe")
    )
    opened = []
    control.open_inbox(
        RuntimePaths(tmp_path / "data"),
        launcher=lambda *_args, **_kwargs: pytest.fail("duplicate launch"),
        browser=lambda url: opened.append(url) or True,
    )
    assert opened and len(calls) == 2


def test_windows_plan_requires_exact_explicit_apply_and_stopped_runtime(tmp_path, monkeypatch):
    from dataclasses import dataclass

    import decision_mesh.windows_setup as windows

    @dataclass(frozen=True)
    class Plan:
        snapshot: str = "a" * 64
        autostart: bool = True
        shortcut: bool = True
        changes: tuple = ("task", "shortcut")

    applied = []
    manager = SimpleNamespace(plan=lambda **kwargs: Plan(), apply=lambda plan: applied.append(plan))
    monkeypatch.setattr(windows, "build_current_user_integration", lambda _: manager)
    root = tmp_path / "data"
    args = [
        "setup",
        "--data-dir",
        str(root),
        "--windows-integration",
        "install",
        "--autostart",
        "--shortcut",
    ]
    code, output, _ = invoke(args)
    assert code == 0 and json.loads(output)["status"] == "plan_only" and not applied
    assert invoke(args + ["--apply-plan", "b" * 64])[0] == 1 and not applied
    with owner_file_lock(root / "runtime.lock", timeout=0):
        assert invoke(args + ["--apply-plan", "a" * 64])[0] == 1
    assert invoke(args + ["--apply-plan", "a" * 64])[0] == 0
    assert len(applied) == 1
    with cli.SQLiteStore(root / "decisionmesh.db") as store:
        assert store.get_settings().autostart


def test_restore_does_not_mix_backup_into_existing_producer_state(tmp_path):
    root = ensure_spool_dir(tmp_path / "data")
    with cli.SQLiteStore(root / "decisionmesh.db") as store:
        backup = store.backup(root / "backup.db")
    target = ensure_spool_dir(tmp_path / "target")
    cli.enroll_producer(target / "producer")
    before = (target / "producer" / "enrollment.json").read_bytes()
    assert invoke(["restore", "--data-dir", str(target), "--backup", str(backup)])[0] == 1
    assert not (target / "decisionmesh.db").exists()
    assert (target / "producer" / "enrollment.json").read_bytes() == before


def test_rt1_explicit_setup_command_verifies_local_capture(tmp_path):
    import threading

    from decision_mesh.runtime import Runtime

    root = tmp_path / "data"
    vault = SimpleNamespace(get_version=lambda: None)
    runtime = Runtime(root, credentials=vault).start()
    thread = threading.Thread(target=runtime.serve)
    thread.start()
    try:
        code, output, errors = invoke(["setup", "--data-dir", str(root), "--verify-local"])
        assert code == 0, errors
        result = json.loads(output)
        assert result["scope"] == "local_runtime"
        assert result["reconciliation_required"] and not result["policy_ready"]
        assert result["environment_verified"] and result["local_capture_verified"]
        assert result["native_qualification"] == "unverified"
        assert result["hook_trust"] == "unverified"
        assert runtime.service.setup.progress().local_capture_verified
        setup_before = (root / "setup.json").read_bytes()
        code, output, errors = invoke(["setup", "--data-dir", str(root), "--status"])
        assert code == 0 and json.loads(output)["local_capture_verified"]
        assert (root / "setup.json").read_bytes() == setup_before
        code, output, errors = invoke(["setup", "--data-dir", str(root), "--reconcile"])
        assert code == 0 and json.loads(output)["ok"]
    finally:
        runtime.request_stop()
        thread.join(5)
        assert not thread.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Installed Windows launcher qualification")
def test_rt4_installed_full_path_launch_ignores_path_selection(tmp_path):
    import hashlib
    import platform
    import subprocess
    import sys
    import sysconfig
    import time
    from pathlib import Path

    project = Path(__file__).parents[1]
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def execute(args, **kwargs):
        return subprocess.run(
            [str(item) for item in args],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
            creationflags=flags,
            **kwargs,
        )

    wheel = os.environ.get("DECISIONMESH_TEST_WHEEL")
    if not wheel:
        import base64
        import csv
        import zipfile
        from io import StringIO

        # Controlled patched qualification artifact; no build tools/network or UI edits.
        original = project / "dist/python-review-1/decision_mesh-0.1.0a1-py3-none-any.whl"
        if not original.is_file():
            pytest.skip(
                "Set DECISIONMESH_TEST_WHEEL to a locally built wheel for installed qualification"
            )
        wheel = tmp_path / original.name
        with zipfile.ZipFile(original) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        for name in (
            "runtime.py",
            "runtime_control.py",
            "runtime_service.py",
            "diagnostics.py",
            "windows_setup.py",
        ):
            files["decision_mesh/" + name] = (project / "src/decision_mesh" / name).read_bytes()
        record = next(name for name in files if name.endswith(".dist-info/RECORD"))
        contents = StringIO()
        writer = csv.writer(contents, lineterminator="\n")
        for name, body in files.items():
            if name != record:
                digest = (
                    base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
                )
                writer.writerow([name, "sha256=" + digest, len(body)])
        writer.writerow([record, "", ""])
        files[record] = contents.getvalue().encode()
        with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
    evidence = {
        "wheel_kind": "supplied"
        if os.environ.get("DECISIONMESH_TEST_WHEEL")
        else "temporary_patched_qualification_only",
        "wheel_sha256": hashlib.sha256(Path(wheel).read_bytes()).hexdigest(),
        "scenarios": [],
    }
    executables = []
    for name in ("selected", "other"):
        environment = tmp_path / name
        result = execute([sys.executable, "-m", "venv", "--without-pip", environment])
        assert result.returncode == 0, result.stderr
        python = environment / "Scripts" / "python.exe"
        result = execute(
            [
                sys.executable,
                "-m",
                "pip",
                "--python",
                python,
                "install",
                "--no-index",
                "--no-deps",
                wheel,
            ]
        )
        assert result.returncode == 0, result.stderr
        # Reuse third-party dependencies only; installed application wins before this path.
        (environment / "Lib" / "site-packages" / "qualification-dependencies.pth").write_text(
            sysconfig.get_path("purelib")
        )
        executables.append((python, environment / "Scripts" / "decisionmesh.exe"))
    selected_python, selected = executables[0]
    other = executables[1][1]
    installed_package = selected_python.parent.parent / "Lib/site-packages/decision_mesh"
    evidence["source_hashes"] = {}
    for name in (
        "runtime.py",
        "runtime_control.py",
        "runtime_service.py",
        "diagnostics.py",
        "windows_setup.py",
    ):
        actual = (installed_package / name).read_bytes()
        if not os.environ.get("DECISIONMESH_TEST_WHEEL"):
            assert actual == (project / "src/decision_mesh" / name).read_bytes()
        evidence["source_hashes"][name] = hashlib.sha256(actual).hexdigest()
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}
    }
    system = str(Path(os.environ["SystemRoot"]) / "System32")
    result = execute(
        [selected_python, "-c", "import decision_mesh.runtime_control as r; print(r.__file__)"],
        cwd=neutral,
        env=env,
    )
    assert result.returncode == 0 and str(tmp_path / "selected") in result.stdout
    for scenario, path_value in (
        ("scripts_absent", system),
        ("selected_scripts", str(selected.parent) + os.pathsep + system),
        ("other_installation_first", str(other.parent) + os.pathsep + system),
    ):
        env["PATH"] = path_value
        data = tmp_path / ("data-" + hashlib.sha256(path_value.encode()).hexdigest()[:8])
        try:
            result = execute(
                [selected, "setup", "--verify-local", "--local-only", "--data-dir", data],
                cwd=neutral,
                env=env,
            )
            assert result.returncode == 0, (scenario, result.stderr)
            state = json.loads(result.stdout)
            assert state["local_capture_verified"] and state["native_qualification"] == "unverified"
            assert state["reconciliation_required"] and not state["policy_ready"]
            signature = hashlib.sha256(
                json.dumps(
                    [str(selected_python.resolve()), platform.python_version(), str(data.resolve())]
                ).encode()
            ).hexdigest()
            assert (
                json.loads((data / "setup.json").read_bytes())["environment_signature"] == signature
            )
            doctor = execute([selected, "doctor", "--data-dir", data], cwd=neutral, env=env)
            assert (
                doctor.returncode == 0
                and json.loads(doctor.stdout)["installed_command"] == "available"
            )
        finally:
            stopped = execute([selected, "stop", "--data-dir", data], cwd=neutral, env=env)
            assert stopped.returncode == 0, stopped.stderr
            deadline = time.monotonic() + 10
            while (data / "runtime.json").exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not (data / "runtime.json").exists()
        evidence["scenarios"].append(
            {
                "path_scenario": scenario,
                "correct_runtime_interpreter": True,
                "verification": True,
                "doctor": True,
                "authenticated_stop": True,
            }
        )
    (tmp_path / "installed-launch-evidence.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, sort_keys=True))


@pytest.mark.parametrize(
    "boundary",
    [
        "valid",
        "other_module",
        "other_interpreter",
        "checkout",
        "entrypoint",
        "unrecorded",
        "duplicate",
        "missing_hash",
        "missing_script",
        "tampered",
        "size_mismatch",
    ],
)
def test_rt4_resolver_checks_distribution_and_record(tmp_path, monkeypatch, boundary):
    import base64
    import hashlib

    lib = tmp_path / "Lib"
    lib.mkdir()
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    module = lib / "runtime_control.py"
    module.write_bytes(b"installed-module")
    executable = scripts / ("decisionmesh.exe" if os.name == "nt" else "decisionmesh")
    body = b"installed-console"
    executable.write_bytes(body)
    entry = SimpleNamespace(
        size=len(body),
        hash=SimpleNamespace(
            mode="sha256",
            value=base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode(),
        ),
    )
    endpoint = SimpleNamespace(
        group="console_scripts", name="decisionmesh", value="decision_mesh.cli:main"
    )
    distribution = SimpleNamespace(
        entry_points=[endpoint],
        files=[entry],
        locate_file=lambda item: executable if item is entry else module,
    )
    if boundary == "other_module":
        distribution.locate_file = lambda item: executable
    elif boundary == "other_interpreter":
        monkeypatch.setattr(control.sysconfig, "get_path", lambda key: str(scripts))
    elif boundary == "entrypoint":
        endpoint.value = "other.cli:main"
    elif boundary == "unrecorded":
        distribution.files = []
    elif boundary == "duplicate":
        distribution.files = [entry, entry]
    elif boundary == "missing_hash":
        entry.hash = None
    elif boundary == "missing_script":
        executable.unlink()
    elif boundary == "tampered":
        executable.write_bytes(b"X" * len(body))
    elif boundary == "size_mismatch":
        entry.size += 1
    elif boundary == "checkout":
        module = tmp_path / "checkout-runtime-control.py"
        module.write_bytes(b"checkout-module")
    if boundary != "other_interpreter":
        monkeypatch.setattr(
            control.sysconfig, "get_path", lambda key: str(lib if key == "purelib" else scripts)
        )
    monkeypatch.setattr(control, "__file__", str(module))
    monkeypatch.setattr(control.metadata, "distribution", lambda name: distribution)
    if boundary == "valid":
        assert control.resolve_installed_console() == executable
    else:
        with pytest.raises(RuntimeErrorCode, match="^installed_command_unavailable$"):
            control.resolve_installed_console()
