import ctypes
import hashlib
import json
import os
import subprocess
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from decision_mesh import capture, windows_native, windows_setup
from decision_mesh.capture import assert_owner_only
from decision_mesh.windows_setup import (
    IntegrationError,
    NativeWindowsBackend,
    ShortcutSpec,
    TaskSpec,
    WindowsIntegration,
    parse_task,
    proposed_hook_addition,
    task_xml,
)

SID = "S-1-5-21-111-222-333-1001"


class Backend:
    def __init__(self):
        self.tasks = {}
        self.links = {}
        self.calls = []
        self.crash = None

    def read_task(self, name):
        return self.tasks.get(name)

    def write_task(self, spec, *, replace, expected=None):
        assert self.tasks.get(spec.name) == expected
        self.calls.append(("task", spec, replace))
        self.tasks[spec.name] = spec
        if self.crash == "task":
            raise SystemExit("synthetic crash after task installation")

    def remove_task(self, name, *, expected):
        assert self.tasks.get(name) == expected
        self.calls.append(("remove_task", name))
        self.tasks.pop(name)

    def read_shortcut(self, path):
        return self.links.get(str(path))

    def write_shortcut(self, spec, *, expected=None):
        assert self.links.get(spec.path) == expected
        self.calls.append(("shortcut", spec))
        self.links[spec.path] = spec
        if self.crash == "shortcut":
            raise SystemExit("synthetic crash after shortcut installation")

    def remove_shortcut(self, path, *, expected):
        assert self.links.get(str(path)) == expected
        self.calls.append(("remove_shortcut", str(path)))
        self.links.pop(str(path))


@pytest.fixture
def integration(tmp_path, monkeypatch):
    # No manager test may touch the real per-user integration lock namespace.
    monkeypatch.setattr(
        windows_setup, "current_user_local_appdata_dir", lambda: tmp_path / "LocalAppData",
        raising=False,
    )
    backend = Backend()
    console = tmp_path / "installed programs" / "decisionmesh.exe"
    console.parent.mkdir()
    console.write_bytes(b"fixture only")
    system = tmp_path / "Windows" / "System32"
    system.mkdir(parents=True)
    (system / "wscript.exe").write_bytes(b"fixture only")
    programs = tmp_path / "Start Menu" / "Programs"
    programs.mkdir(parents=True)
    options = {
        "data_dir": tmp_path / "local data",
        "programs_dir": programs,
        "user_sid": SID,
        "backend": backend,
        "console_resolver": lambda: console,
        "windows_dir": system.parent,
    }
    return WindowsIntegration(**options), backend, options, console


@pytest.fixture(autouse=True)
def forbid_native_integration(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real task/shortcut integration is forbidden in synthetic tests")
    monkeypatch.setattr(windows_native, "_shell_link", forbidden)
    monkeypatch.setattr(windows_native, "read_task_document", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.mark.parametrize("kind", ["task", "shortcut"])
def test_shared_integration_lock_serializes_different_data_roots(
    integration, monkeypatch, tmp_path, kind
):
    manager, _backend, options, _ = integration
    peer = WindowsIntegration(**(options | {"data_dir": tmp_path / "peer data"}))
    selection = {"autostart": kind == "task", "shortcut": kind == "shortcut"}
    first, second = manager.plan(**selection), peer.plan(**selection)
    original = windows_setup.atomic_write_owner_only
    outcomes = []

    def interleave(path, body, **kwargs):
        result = original(path, body, **kwargs)
        if Path(path) == manager.manifest_path and not outcomes:
            outcomes.append("attempted")
            with pytest.raises(IntegrationError, match="integration_busy"):
                peer.apply(second)
        return result

    monkeypatch.setattr(windows_setup, "atomic_write_owner_only", interleave)
    manager.apply(first)
    assert outcomes == ["attempted"]
    assert not peer.manifest_path.exists()
    assert not manager.plan(operation="repair").changes
    with pytest.raises(IntegrationError, match="preserved"):
        peer.apply(second)
    manager.apply(manager.plan(operation="remove"))
    peer.apply(peer.plan(**selection))
    assert not peer.plan(operation="repair").changes


@pytest.mark.parametrize("kind", ["task", "shortcut", "launcher"])
def test_edit_during_remove_journal_is_preserved_with_recoverable_partial_state(
    integration, monkeypatch, kind
):
    manager, backend, options, _ = integration
    manager.apply(manager.plan(autostart=True, shortcut=True))
    plan = manager.plan(operation="remove")
    original = windows_setup.atomic_write_owner_only
    edited = []
    launcher = manager.data_dir / "launch-run.vbs"
    task_before = backend.tasks[manager.task_name]
    link_before = backend.links[str(manager.shortcut_path)]
    launch_before = launcher.read_bytes()

    def interleave(path, body, **kwargs):
        result = original(path, body, **kwargs)
        if Path(path) == manager.manifest_path and not edited:
            edited.append(True)
            if kind == "task":
                backend.tasks[manager.task_name] = replace(task_before, arguments="user edit")
            elif kind == "shortcut":
                backend.links[str(manager.shortcut_path)] = replace(link_before, arguments="user edit")
            else:
                launcher.write_text("user edit", encoding="utf-16")
        return result

    calls_before = list(backend.calls)
    with monkeypatch.context() as patch:
        patch.setattr(windows_setup, "atomic_write_owner_only", interleave)
        with pytest.raises(IntegrationError, match="apply_incomplete"):
            manager.apply(plan)
    assert backend.calls == calls_before
    assert backend.tasks[manager.task_name].arguments == ("user edit" if kind == "task" else task_before.arguments)
    assert backend.links[str(manager.shortcut_path)].arguments == ("user edit" if kind == "shortcut" else link_before.arguments)
    assert launcher.read_bytes() == ("user edit".encode("utf-16") if kind == "launcher" else launch_before)
    assert manager._manifest()["pending"] is not None
    reopened = WindowsIntegration(**options)
    with pytest.raises(IntegrationError, match="preserved"):
        reopened.plan(operation="remove")
    # Only the fixture editor restores its edit; the product never overwrites it.
    backend.tasks[manager.task_name], backend.links[str(manager.shortcut_path)] = task_before, link_before
    launcher.write_bytes(launch_before)
    reopened.apply(reopened.plan(operation="remove"))
    assert not backend.tasks and not backend.links and not launcher.exists()


def test_partial_remove_retains_journal_and_later_edited_shortcut(integration, monkeypatch):
    manager, backend, options, _ = integration
    manager.apply(manager.plan(autostart=True, shortcut=True))
    original_link = backend.links[str(manager.shortcut_path)]
    original = windows_setup.atomic_write_owner_only
    journal_writes = []

    def interleave(path, body, **kwargs):
        result = original(path, body, **kwargs)
        if Path(path) == manager.manifest_path:
            journal_writes.append(True)
            if len(journal_writes) == 2:  # Initial intent, then successful task removal.
                backend.links[str(manager.shortcut_path)] = replace(original_link, arguments="edited")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(windows_setup, "atomic_write_owner_only", interleave)
        with pytest.raises(IntegrationError, match="apply_incomplete"):
            manager.apply(manager.plan(operation="remove"))
    assert manager.task_name not in backend.tasks
    assert backend.links[str(manager.shortcut_path)].arguments == "edited"
    manifest = manager._manifest()
    assert manifest["task"] is None and manifest["pending"] is not None
    assert (manager.data_dir / "launch-run.vbs").exists()
    reopened = WindowsIntegration(**options)
    with pytest.raises(IntegrationError, match="preserved"):
        reopened.plan(operation="remove")
    backend.links[str(manager.shortcut_path)] = original_link
    reopened.apply(reopened.plan(operation="remove"))
    assert not backend.tasks and not backend.links


def test_shared_lock_is_retained_and_ignores_environment_data_root(integration, monkeypatch, tmp_path):
    manager, _backend, options, _ = integration
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "untrusted environment"))
    manager.apply(manager.plan(autostart=True))
    lock = tmp_path / "LocalAppData/DecisionMesh-Integration" / (hashlib.sha256(SID.encode()).hexdigest() + ".lock")
    assert_owner_only(lock)
    original_id = lock.stat().st_ino
    reopened = WindowsIntegration(**options)
    reopened.apply(reopened.plan(operation="remove"))
    assert lock.exists() and lock.stat().st_ino == original_id
    assert not (tmp_path / "untrusted environment").exists()


def test_launcher_edit_during_fsync_is_preserved_with_pending_recovery(
    integration, monkeypatch, tmp_path
):
    manager, _backend, options, _ = integration
    manager.apply(manager.plan(autostart=True))
    upgraded = tmp_path / "upgraded-decisionmesh" / "decisionmesh.exe"
    upgraded.parent.mkdir()
    upgraded.write_bytes(b"fixture only")
    options = options | {"console_resolver": lambda: upgraded}
    manager = WindowsIntegration(**options)
    target = manager.data_dir / "launch-run.vbs"
    original_bytes = target.read_bytes()
    changed = original_bytes + "\r\n' ordinary edit during fsync\r\n".encode("utf-16-le")
    real_write, real_fsync = windows_setup.atomic_write_owner_only, capture.os.fsync
    active, injected = [], []

    def write(path, body, **kw):
        active.append(Path(path))
        try:
            return real_write(path, body, **kw)
        finally:
            active.pop()

    def fsync(fd):
        result = real_fsync(fd)
        if active and active[-1] == target and not injected:
            target.write_bytes(changed)
            injected.append(True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(windows_setup, "atomic_write_owner_only", write)
        patch.setattr(capture.os, "fsync", fsync)
        with pytest.raises(IntegrationError, match="apply_incomplete"):
            manager.apply(manager.plan(operation="repair"))
    assert injected == [True] and target.read_bytes() == changed
    assert manager._manifest()["pending"] is not None
    reopened = WindowsIntegration(**options)
    with pytest.raises(IntegrationError, match="preserved"):
        reopened.plan(operation="repair")
    target.write_bytes(original_bytes)  # The fixture editor restores its own edit.
    reopened.apply(reopened.plan(operation="repair"))
    assert str(upgraded) in target.read_text(encoding="utf-16")
    assert reopened._manifest()["pending"] is None


def test_staging_crash_recovery_leaves_no_extra_shortcut(integration, monkeypatch):
    _manager, _backend, options, _ = integration
    backend = object.__new__(NativeWindowsBackend)
    backend.data_dir = options["data_dir"]
    options = options | {"backend": backend}
    monkeypatch.setattr(backend, "read_task", lambda name: None)

    def shell_link(path, spec=None):
        if spec is not None:
            path.write_text(json.dumps(asdict(spec)), encoding="utf-8")
        else:
            return replace(ShortcutSpec(**json.loads(path.read_text(encoding="utf-8"))), path=str(path))

    monkeypatch.setattr(windows_native, "_shell_link", shell_link)
    manager = WindowsIntegration(**options)
    snapshot = {}

    class SnapshotCrash(BaseException):
        pass

    def stage(path, spec=None):
        result = shell_link(path, spec)
        if spec is not None and path.name.startswith(".decisionmesh-"):
            snapshot.update(path=path, body=path.read_bytes(), journal=manager.manifest_path.read_bytes())
            raise SnapshotCrash()
        return result

    with monkeypatch.context() as patch:
        patch.setattr(windows_native, "_shell_link", stage)
        with pytest.raises(SnapshotCrash):
            manager.apply(manager.plan(shortcut=True))
    # Rehydrate exactly the durable state a process exit would retain, because
    # Python exception unwinding ran finally. No native COM/process exit occurs.
    staged = snapshot["path"]
    assert not staged.exists() and not manager.shortcut_path.exists()
    staged.write_bytes(snapshot["body"])
    assert manager.manifest_path.read_bytes() == snapshot["journal"]
    reopened = WindowsIntegration(**options)
    reopened.apply(reopened.plan(operation="repair"))
    assert list(reopened.programs_dir.glob("*.lnk")) == [reopened.shortcut_path]
    reopened.apply(reopened.plan(operation="remove"))
    assert not list(reopened.programs_dir.glob("*.lnk"))
    assert staged.exists() and staged.suffix == ".tmp"  # Inert residue, never swept.
    assert reopened._manifest()["pending"] is None
    assert not (reopened.data_dir / "launch-open.vbs").exists()


def test_default_off_plan_is_read_only_and_apply_has_no_os_operations(integration):
    manager, backend, *_ = integration
    plan = manager.plan()
    assert not plan.changes and not manager.data_dir.exists()
    manager.apply(plan)
    assert not backend.calls and not backend.tasks and not backend.links


def test_install_idempotent_repair_upgrade_and_exact_remove(integration, tmp_path):
    manager, backend, options, _console = integration
    backend.tasks["OtherApp"] = TaskSpec("OtherApp", "foreign", SID, "foreign.exe", "")
    plan = manager.plan(autostart=True, shortcut=True)
    assert set(plan.changes) == {"task", "shortcut", "launchers"} and not backend.calls
    assert plan.task_spec.sid == SID and plan.shortcut_spec.path == str(manager.shortcut_path)
    assert set(dict(plan.launchers)) == {"run", "open"}
    manager.apply(plan)
    assert_owner_only(manager.manifest_path)
    launch = (manager.data_dir / "launch-run.vbs").read_text(encoding="utf-16")
    assert "run --data-dir" in launch and "0, False" in launch
    task = backend.tasks[manager.task_name]
    assert task.command.endswith("wscript.exe") and "//B //Nologo" in task.arguments
    assert parse_task(task.name, task_xml(task)) == task
    assert "LeastPrivilege" in task_xml(task).decode("utf-16")
    before = list(backend.calls)
    manager.apply(manager.plan(autostart=True, shortcut=True))
    assert backend.calls == before
    upgraded = tmp_path / "upgrade" / "decisionmesh.exe"
    upgraded.parent.mkdir()
    upgraded.write_bytes(b"new fixture")
    repaired = WindowsIntegration(**(options | {"console_resolver": lambda: upgraded}))
    repair = repaired.plan(autostart=True, shortcut=True, operation="repair")
    assert repair.changes == ("launchers",)
    repaired.apply(repair)
    assert str(upgraded) in (manager.data_dir / "launch-run.vbs").read_text(encoding="utf-16")
    saved = manager.data_dir / "preserved.db"
    saved.write_bytes(b"user data")
    repaired.apply(repaired.plan(operation="remove"))
    assert backend.tasks == {"OtherApp": TaskSpec("OtherApp", "foreign", SID, "foreign.exe", "")}
    assert not backend.links and saved.read_bytes() == b"user data"
    assert not (manager.data_dir / "launch-run.vbs").exists()
    repaired.apply(repaired.plan(operation="remove"))


@pytest.mark.parametrize("kind", ["task", "shortcut"])
def test_foreign_entry_same_display_name_is_never_touched(integration, kind):
    manager, backend, *_ = integration
    if kind == "task":
        backend.tasks[manager.task_name] = TaskSpec(
            manager.task_name, "foreign", SID, "foreign.exe", ""
        )
    else:
        backend.links[str(manager.shortcut_path)] = ShortcutSpec(
            str(manager.shortcut_path), "foreign", "foreign.exe", ""
        )
    with pytest.raises(IntegrationError, match="preserved"):
        manager.plan(autostart=True, shortcut=True)
    assert not backend.calls


def test_modified_owned_entry_and_stale_plan_refused(integration):
    manager, backend, *_ = integration
    plan = manager.plan(autostart=True)
    backend.tasks[manager.task_name] = TaskSpec(
        manager.task_name, manager.owner, SID, "modified.exe", ""
    )
    with pytest.raises(IntegrationError, match="preserved"):
        manager.apply(plan)
    assert not backend.calls
    backend.tasks.clear()
    manager.apply(manager.plan(autostart=True))
    plan = manager.plan(operation="remove")
    backend.tasks[manager.task_name] = replace(
        backend.tasks[manager.task_name], arguments="changed"
    )
    with pytest.raises(IntegrationError, match="preserved"):
        manager.apply(plan)


def test_forged_plan_never_mutates(integration):
    manager, backend, *_ = integration
    plan = manager.plan(autostart=True)
    with pytest.raises(IntegrationError, match="plan_required"):
        manager.apply(replace(plan))
    assert not backend.calls


def test_crash_after_task_write_has_durable_exact_ownership_for_repair(integration):
    manager, backend, options, _ = integration
    backend.crash = "task"
    with pytest.raises(SystemExit):
        manager.apply(manager.plan(autostart=True))
    backend.crash = None
    reopened = WindowsIntegration(**options)
    reopened.apply(reopened.plan(autostart=True, operation="repair"))
    assert backend.tasks[manager.task_name].owner == manager.owner


def test_quote_and_expansion_paths_are_refused(integration, tmp_path):
    _, _, options, _ = integration
    for path in (Path("relative"), tmp_path / 'bad"dir', tmp_path / "bad\ndir"):
        with pytest.raises(IntegrationError):
            WindowsIntegration(**(options | {"data_dir": path}))
    unsafe = WindowsIntegration(**(options | {"data_dir": tmp_path / "%PATH%"}))
    with pytest.raises(IntegrationError):
        unsafe.plan(autostart=True)


@pytest.mark.parametrize(
    "old,new",
    [
        ("LeastPrivilege", "HighestAvailable"),
        ("InteractiveToken", "Password"),
        ("<Hidden>true</Hidden>", "<Hidden>false</Hidden>"),
        (SID, "S-1-5-18"),
    ],
)
def test_task_xml_rejects_privilege_or_owner_changes(integration, old, new):
    manager, backend, *_ = integration
    manager.apply(manager.plan(autostart=True))
    spec = backend.tasks[manager.task_name]
    xml = task_xml(spec).decode("utf-16").replace(old, new, 1).encode("utf-16")
    with pytest.raises(IntegrationError):
        parse_task(spec.name, xml)


def test_hidden_native_command_has_exact_argv_and_no_shell(monkeypatch, tmp_path):
    backend = object.__new__(NativeWindowsBackend)
    backend.schtasks = tmp_path / "schtasks.exe"
    calls = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs)) or subprocess.CompletedProcess(argv, 0, b"", b"")
        ),
    )
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    backend._run(["/Delete", "/TN", "DecisionMesh-test", "/F"])
    argv, options = calls[0]
    assert argv[1:] == ["/Delete", "/TN", "DecisionMesh-test", "/F"]
    assert options["creationflags"] == 0x08000000
    assert options["shell"] is False and options["timeout"] == 15
    assert options["stdin"] == subprocess.DEVNULL


def test_hook_is_exact_proposal_only_no_write_no_trust(integration):
    manager, _, _, console = integration
    capture = console.with_name("decisionmesh-capture.exe")
    capture.write_bytes(b"fixture")
    result = proposed_hook_addition(
        capture_executable=capture,
        spool=manager.data_dir / "spool",
        policy=manager.data_dir / "policy.json",
    )
    command = result["hooks"]["PermissionRequest"][0]["hooks"][0]["command"]
    assert str(capture) in command and "--spool" in command and "--policy" in command
    assert not manager.data_dir.exists()
    assert "trust" not in str(result) and "allow" not in str(result)


def test_unicode_launcher_has_windows_unicode_encoding(integration, tmp_path):
    _, _, options, _ = integration
    manager = WindowsIntegration(**(options | {"data_dir": tmp_path / "नमस्ते"}))
    manager.apply(manager.plan(autostart=True))
    raw = (manager.data_dir / "launch-run.vbs").read_bytes()
    assert raw.startswith(b"\xff\xfe") and "नमस्ते" in raw.decode("utf-16")
    assert not manager.plan(autostart=True).changes


def test_no_elevation_or_wildcard_deletion_commands_in_native_adapter(monkeypatch, tmp_path):
    backend = object.__new__(NativeWindowsBackend)
    backend.data_dir = tmp_path / "owned"
    captured = []
    monkeypatch.setattr(
        backend, "_run", lambda args: captured.append(args) or subprocess.CompletedProcess(args, 0)
    )
    spec = TaskSpec(
        "DecisionMesh-owned",
        "DecisionMesh/v1/owner",
        SID,
        "C:\\Windows\\System32\\wscript.exe",
        '"C:\\owned\\launch.vbs"',
    )
    monkeypatch.setattr(backend, "read_task", lambda name: None)
    backend.write_task(spec, replace=False)
    monkeypatch.setattr(backend, "read_task", lambda name: spec)
    backend.remove_task(spec.name, expected=spec)
    assert captured[0][:3] == ["/Create", "/TN", spec.name]
    assert "/F" not in captured[0] and "/RU" not in captured[0] and "/RP" not in captured[0]
    assert captured[1] == ["/Delete", "/TN", spec.name, "/F"]
    assert not list(backend.data_dir.glob("task-*.xml"))


def test_doctor_repair_preserves_previous_explicit_opt_ins(integration):
    manager, backend, *_ = integration
    manager.apply(manager.plan(autostart=True, shortcut=True))
    plan = manager.plan(operation="repair")
    assert plan.autostart and plan.shortcut and not plan.changes
    before = list(backend.calls)
    manager.apply(plan)
    assert backend.calls == before


def test_os_success_without_observed_install_is_incomplete(integration, monkeypatch):
    manager, backend, *_ = integration
    monkeypatch.setattr(backend, "write_task", lambda spec, replace, expected: None)
    with pytest.raises(IntegrationError, match="apply_incomplete"):
        manager.apply(manager.plan(autostart=True))
    assert manager.plan(operation="repair").changes == ("task",)


def test_current_user_factory_is_read_only_and_uses_native_context(monkeypatch, tmp_path):
    data, programs = tmp_path / "unused-data", tmp_path / "redirected-programs"
    backend = Backend()
    monkeypatch.setattr(windows_setup, "current_user_sid", lambda: SID)
    monkeypatch.setattr(windows_setup, "current_user_programs_dir", lambda: programs)
    monkeypatch.setattr(windows_setup, "NativeWindowsBackend", lambda data_dir: backend)
    manager = windows_setup.build_current_user_integration(data)
    assert manager.sid == SID and manager.programs_dir == programs
    assert not data.exists() and not programs.exists() and not backend.calls


@pytest.mark.skipif(os.name != "nt", reason="Windows API adapter with mocked process")
@pytest.mark.parametrize(
    "body,valid",
    [(f'"user","{SID}"\r\n'.encode(), True), (b'"user","S-1-5-18"', False), (b'"bad"', False)],
)
def test_native_user_sid_query_is_bounded_hidden_and_rejects_service_accounts(
    monkeypatch, tmp_path, body, valid
):
    system = tmp_path / "Windows" / "System32"
    system.mkdir(parents=True)
    (system / "whoami.exe").write_bytes(b"not executed")
    monkeypatch.setenv("SystemRoot", str(system.parent))
    calls = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: (
            calls.append((args, kwargs)) or subprocess.CompletedProcess(args, 0, body, b"")
        ),
    )
    if valid:
        assert windows_native.current_user_sid() == SID
    else:
        with pytest.raises(IntegrationError, match="identity_unavailable"):
            windows_native.current_user_sid()
    args, options = calls[0]
    assert args[1:] == ["/user", "/fo", "csv", "/nh"]
    assert options["timeout"] == 5 and options["creationflags"] == subprocess.CREATE_NO_WINDOW
    assert options["shell"] is False


@pytest.mark.skipif(os.name != "nt", reason="Windows API adapter with mocked DLLs")
@pytest.mark.parametrize("hresult", [0, -1])
@pytest.mark.parametrize("folder_api,folder_id,failure", [
    ("current_user_programs_dir", "a77f5d77-2e2b-44c3-a6a2-aba601054a51", "start_menu_unavailable"),
    ("current_user_local_appdata_dir", "f1b32785-6fba-4fcf-9d55-7b8e7f157091", "local_appdata_unavailable"),
])
def test_native_programs_folder_uses_current_token_and_frees_allocated_path(
    monkeypatch, tmp_path, hresult, folder_api, folder_id, failure
):
    programs = tmp_path / "redirected-programs"
    programs.mkdir()
    buffer = ctypes.create_unicode_buffer(str(programs))
    freed = []

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    class Library:
        pass

    shell, ole = Library(), Library()

    def query(folder, flags, token, output):
        assert (
            ctypes.string_at(folder, 16)
            == uuid.UUID(folder_id).bytes_le
        )
        assert flags == 0 and token is None
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buffer)
        return hresult

    shell.SHGetKnownFolderPath = Function(query)
    ole.CoTaskMemFree = Function(lambda pointer: freed.append(pointer.value))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name: shell if name == "shell32" else ole)
    if hresult == 0:
        assert getattr(windows_native, folder_api)() == programs
    else:
        with pytest.raises(IntegrationError, match=failure):
            getattr(windows_native, folder_api)()
    assert freed == [ctypes.addressof(buffer)]


@pytest.mark.parametrize("change", ["working_directory", "repetition", "battery_setting"])
@pytest.mark.parametrize("stale_plan", [False, True])
def test_native_task_semantic_changes_are_preserved_at_plan_apply_boundary(
    integration, monkeypatch, change, stale_plan
):
    manager, backend, *_ = integration
    manager.apply(manager.plan(autostart=True))
    plan = manager.plan(operation="remove") if stale_plan else None
    spec = backend.tasks[manager.task_name]
    root = ET.fromstring(task_xml(spec))
    ns = {"t": windows_native.TASK_NS}
    tag = lambda name: "{" + windows_native.TASK_NS + "}" + name
    if change == "working_directory":
        ET.SubElement(root.find("t:Actions/t:Exec", ns), tag("WorkingDirectory")).text = "C:\\peer"
    elif change == "repetition":
        repetition = ET.SubElement(root.find("t:Triggers/t:LogonTrigger", ns), tag("Repetition"))
        ET.SubElement(repetition, tag("Interval")).text = "PT1M"
    else:
        root.find("t:Settings/t:DisallowStartIfOnBatteries", ns).text = "true"
    modified_xml = ET.tostring(root, encoding="utf-16")
    monkeypatch.setattr(backend, "read_task", lambda name: parse_task(name, modified_xml))
    before = list(backend.calls)
    with pytest.raises(IntegrationError):
        if stale_plan:
            manager.apply(plan)
        else:
            manager.apply(manager.plan(operation="remove"))
    assert backend.tasks[manager.task_name] == spec and backend.calls == before


def test_task_parser_accepts_only_semantically_identical_serialization(integration):
    manager, backend, *_ = integration
    manager.apply(manager.plan(autostart=True))
    spec = backend.tasks[manager.task_name]
    root = ET.fromstring(task_xml(spec))
    ET.indent(root, space="    ")
    assert parse_task(spec.name, ET.tostring(root, encoding="utf-8")) == spec


@pytest.mark.parametrize("kind", ["task", "shortcut", "launcher"])
@pytest.mark.parametrize("failure", [IntegrationError, SystemExit])
@pytest.mark.parametrize("recovery", ["repair", "remove"])
def test_interrupted_install_failed_remove_preserves_exact_recovery_ownership(
    integration, monkeypatch, kind, failure, recovery
):
    manager, backend, options, _ = integration
    selection = {"autostart": kind != "shortcut", "shortcut": kind == "shortcut"}
    target = manager.data_dir / ("launch-open.vbs" if kind == "shortcut" else "launch-run.vbs")
    with monkeypatch.context() as patch:
        if kind == "launcher":
            original = windows_setup.atomic_write_owner_only

            def interrupted_write(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if Path(path) == target:
                    raise SystemExit("synthetic crash after launcher publication")
                return result

            patch.setattr(windows_setup, "atomic_write_owner_only", interrupted_write)
        else:
            backend.crash = kind
        with pytest.raises(SystemExit):
            manager.apply(manager.plan(**selection))
    backend.crash = None
    reopened = WindowsIntegration(**options)
    remove_plan = reopened.plan(operation="remove")

    def fail_before_mutation(*args, **kwargs):
        raise failure("synthetic removal failure")

    with monkeypatch.context() as patch:
        if kind == "task":
            patch.setattr(backend, "remove_task", fail_before_mutation)
        elif kind == "shortcut":
            patch.setattr(backend, "remove_shortcut", fail_before_mutation)
        else:
            original_unlink = Path.unlink

            def interrupted_unlink(path, *args, **kwargs):
                if path == target:
                    fail_before_mutation()
                return original_unlink(path, *args, **kwargs)

            patch.setattr(Path, "unlink", interrupted_unlink)
        with pytest.raises(failure):
            reopened.apply(remove_plan)
    assert target.exists()
    if kind == "task":
        assert manager.task_name in backend.tasks
    elif kind == "shortcut":
        assert str(manager.shortcut_path) in backend.links
    final = WindowsIntegration(**options)
    final.apply(final.plan(operation=recovery))
    assert manager.task_name not in backend.tasks
    assert str(manager.shortcut_path) not in backend.links
    assert not target.exists()


@pytest.mark.parametrize("kind", ["task", "shortcut", "launcher"])
def test_unobserved_replacement_retains_original_ownership(
    integration, monkeypatch, tmp_path, kind
):
    manager, backend, options, _ = integration
    manager.apply(manager.plan(autostart=True, shortcut=True))
    if kind == "launcher":
        executable = tmp_path / "upgraded" / "decisionmesh.exe"
        executable.parent.mkdir()
        executable.write_bytes(b"fixture")
        changed_options = options | {"console_resolver": lambda: executable}
    else:
        system = tmp_path / "alternate-windows" / "System32"
        system.mkdir(parents=True)
        (system / "wscript.exe").write_bytes(b"fixture")
        changed_options = options | {"windows_dir": system.parent}
    upgraded = WindowsIntegration(**changed_options)
    with monkeypatch.context() as patch:
        if kind == "task":
            patch.setattr(backend, "write_task", lambda *args, **kwargs: None)
        elif kind == "shortcut":
            patch.setattr(backend, "write_shortcut", lambda *args, **kwargs: None)
        else:
            original = windows_setup.atomic_write_owner_only

            def unobserved_write(path, *args, **kwargs):
                return (
                    Path(path) if Path(path).suffix == ".vbs" else original(path, *args, **kwargs)
                )

            patch.setattr(windows_setup, "atomic_write_owner_only", unobserved_write)
        with pytest.raises(IntegrationError):
            upgraded.apply(upgraded.plan(operation="repair"))
    restarted = WindowsIntegration(**changed_options)
    restarted.apply(restarted.plan(operation="remove"))
    assert not backend.tasks and not backend.links


@pytest.mark.parametrize("boundary", ["valid", "missing", "wrong_name"])
def test_rt4_windows_integration_uses_verified_installation_resolver(
    tmp_path, monkeypatch, boundary
):
    from decision_mesh import runtime_control

    executable = tmp_path / ("decisionmesh.exe" if boundary != "wrong_name" else "other.exe")
    executable.write_bytes(b"resolver fixture")
    calls = []

    def resolve():
        calls.append(True)
        if boundary == "missing":
            raise runtime_control.RuntimeErrorCode("installed_command_unavailable")
        return executable

    monkeypatch.setattr(runtime_control, "resolve_installed_console", resolve)
    monkeypatch.setenv("PATH", str(tmp_path / "unrelated-installation"))
    if boundary == "valid":
        assert windows_setup.resolve_console_script() == executable
    else:
        expected = (
            "installed_entry_point_missing"
            if boundary == "missing"
            else "installed_entry_point_invalid"
        )
        with pytest.raises(IntegrationError, match="^" + expected + "$"):
            windows_setup.resolve_console_script()
    assert calls == [True]
