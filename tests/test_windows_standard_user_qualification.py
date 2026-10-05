"""Safety tests only: fake WinAPI/process adapters and task-owned temporary files."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


q = load("standard_qualification", "tools/release/check_windows_standard_user.py")
native = load("standard_native", "tools/release/windows_standard_user_native.py")
SID = "S-1-5-21-101-202-303-1002"
PARENT = "S-1-5-21-101-202-303-1001"
NONCE = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def no_real_native_or_process(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real_native_or_process_forbidden")
    monkeypatch.setattr(ctypes, "WinDLL", forbidden, raising=False)
    monkeypatch.setattr(q.subprocess, "Popen", forbidden)
    monkeypatch.setattr(q.subprocess, "run", forbidden)


def token(sid=SID, parent=False):
    return {
        "sid": sid, "groups": [{"sid": q.ADMIN if parent else "S-1-5-32-545",
                               "attributes": 7}],
        "elevated": parent, "elevation_type": 1,
        "integrity": "S-1-16-12288" if parent else "S-1-16-8192", "token_type": 1,
    }


@pytest.fixture
def case(tmp_path):
    env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
           "RUNNER_OS": "Windows", "RUNNER_TEMP": str(tmp_path),
           "SystemRoot": str(tmp_path / "windows")}
    fixture = tmp_path / ("decisionmesh-standard-user-" + NONCE)
    inputs = {"schema_version": 1, "wheelhouse": []}
    for key, name in (("python", "python.exe"), ("wheel", "decision_mesh-0.1.0a1.whl"),
                      ("checker", "check_python_distribution.py"), ("dependency", "dep.whl")):
        path = tmp_path / name
        if path.suffix == ".whl":
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("synthetic-1.dist-info/METADATA", "Name: synthetic\nVersion: 1\n")
        else:
            path.write_bytes(name.encode())
        value = {"path": str(path), "sha256": q.digest(path)}
        if key == "dependency":
            inputs["wheelhouse"].append(value)
        else:
            inputs[key] = value
    return fixture, inputs, env


class FakeNative:
    def __init__(self, fixture, *, fail=None):
        self.fixture, self.fail, self.calls = fixture, fail, []
        self.current = None
        self.profile = fixture.parent / ("profile-" + NONCE)
        self.password = None
        self.job_alive = False
        self.exit = False

    def hit(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("never-log-" + (self.password.value if self.password else "private"))

    def preflight(self):
        self.hit("preflight")
        return token(PARENT, True)

    def account(self, name):
        self.hit("account")
        return self.current.copy() if self.current else None

    def add_account(self, name, password, marker):
        self.password = password
        self.hit("add_account")
        self.current = {"name": name, "sid": SID, "comment": marker}

    def logon(self, name, password):
        self.hit("logon")
        assert password is self.password
        return "token"

    def token_info(self, value):
        self.hit("token_info")
        return token()

    def token(self, process):
        self.hit("child_token")
        return token()

    def desktop_access(self, value):
        self.hit("desktop_access")

    def create_profile(self, name, sid):
        self.hit("create_profile")
        self.profile.mkdir()
        return self.profile

    def profile_path(self, sid):
        self.hit("profile_path")
        return self.profile

    def protect(self, path, owner, grants):
        self.hit("protect")
        assert path.is_relative_to(self.fixture)

    def launch(self, name, password, argv, env, cwd):
        self.hit("launch")
        assert password is self.password and password.value
        assert password.value not in json.dumps([argv, env])
        assert env["PIP_NO_INDEX"] == "1" and env["USERPROFILE"] == str(self.profile)
        assert "--run-hosted" in argv and "-I" in argv and "-B" in argv
        assert cwd == self.profile
        return SimpleNamespace(process="owned-process", thread="owned-thread")

    def job(self, process):
        self.hit("job")
        self.job_alive = True
        return "owned-job"

    def resume(self, thread):
        self.hit("resume")
        self.exit = True
        self.job_alive = False
        (self.fixture / "out/result.json").write_text(json.dumps({
            "status": "PASS", "sid": SID, "runtime_exited": True, "lifetime_lock_released": True
        }))

    def wait(self, process, timeout):
        self.hit("wait")
        return self.exit

    def exit_code(self, process):
        self.hit("exit_code")
        return 0

    def job_empty(self, job, timeout=10):
        self.hit("job_empty")
        return not self.job_alive

    def terminate(self, handle, *, job):
        self.hit("terminate_job" if job else "terminate_suspended")
        assert handle in {"owned-job", "owned-process"}
        self.exit, self.job_alive = True, False

    def close(self, handle):
        self.hit("close_" + str(handle))

    def delete_profile(self, sid, profile):
        self.hit("delete_profile")
        assert sid == SID and profile == self.profile
        self.profile.rmdir()

    delete_account = native.Native.delete_account  # Exercise the real guard over fake calls.

    def call(self, lib, name, result, types, *args):
        assert (lib, name, args) == ("netapi32", "NetUserDel", (None, self.current["name"]))
        self.hit("delete_account")
        self.current = None
        return 0


def run(case, api):
    fixture, inputs, env = case
    return q.execute(fixture, inputs, api, env, enabled=True, platform="nt")


def test_complete_fake_lifecycle_has_ordered_identity_checks_and_cleanup(case):
    api = FakeNative(case[0])
    result = run(case, api)
    assert result["status"] == "PASS" and result["cleanup_complete"]
    assert not case[0].exists() and api.current is None
    assert api.password.value == ""
    assert api.calls.index("child_token") < api.calls.index("job") < api.calls.index("resume")
    assert api.calls.index("close_owned-process") < api.calls.index("delete_profile")
    assert api.calls.index("delete_profile") < api.calls.index("delete_account")
    assert api.calls[api.calls.index("delete_account") - 1] == "account"


@pytest.mark.parametrize("key,value", [
    ("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"), ("RUNNER_TEMP", ""),
])
def test_runner_guards_precede_native_calls(case, key, value):
    fixture, inputs, env = case
    env[key] = value
    api = FakeNative(fixture)
    with pytest.raises(q.QualificationError):
        q.execute(fixture, inputs, api, env, enabled=True, platform="nt")
    assert not api.calls


@pytest.mark.parametrize("enabled,platform", [(False, "nt"), (True, "posix")])
def test_explicit_execution_and_windows_are_required(case, enabled, platform):
    fixture, inputs, env = case
    api = FakeNative(fixture)
    with pytest.raises(q.QualificationError):
        q.execute(fixture, inputs, api, env, enabled=enabled, platform=platform)
    assert not api.calls


@pytest.mark.parametrize("update", [
    {"sid": q.SYSTEM}, {"sid": PARENT}, {"groups": [{"sid": q.ADMIN, "attributes": 16}]},
    {"elevated": True}, {"elevation_type": 3}, {"integrity": "S-1-16-12288"},
    {"integrity": "S-1-16-4096"}, {"token_type": 2}, {"groups": None},
])
def test_standard_token_refuses_admin_filtered_unknown_or_wrong_identity(update):
    value = token()
    value.update(update)
    with pytest.raises(q.QualificationError):
        q.validate_token(value, SID)


def test_existing_account_never_deleted_or_reused(case):
    api = FakeNative(case[0])
    api.current = {"name": "foreign", "sid": SID, "comment": "foreign"}
    with pytest.raises(q.QualificationError, match="account_already_exists"):
        run(case, api)
    assert "add_account" not in api.calls and "delete_account" not in api.calls


@pytest.mark.parametrize("failure", ["logon", "token_info"])
def test_preprofile_failures_clean_only_the_created_account_without_secret_output(case, failure):
    api = FakeNative(case[0], fail=failure)
    result = run(case, api)
    assert result["status"] == "FAILED_OR_UNSUPPORTED"
    assert result["cleanup_complete"] and api.current is None
    assert api.password.value == ""
    assert "never-log" not in json.dumps(result)
    assert "create_profile" not in api.calls and "launch" not in api.calls


def test_account_creation_failure_never_calls_delete(case):
    api = FakeNative(case[0], fail="add_account")
    result = run(case, api)
    assert result["status"] == "FAILED_OR_UNSUPPORTED"
    assert "delete_account" not in api.calls and api.password.value == ""


def test_profile_creation_uncertainty_preserves_account(case):
    api = FakeNative(case[0], fail="create_profile")
    result = run(case, api)
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN"
    assert "delete_account" not in api.calls


def test_replaced_account_prevents_profile_or_account_deletion(case):
    api = FakeNative(case[0])
    old_resume = api.resume
    def changed(thread):
        old_resume(thread)
        api.current["sid"] = "S-1-5-21-999-999-999-999"
    api.resume = changed
    result = run(case, api)
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN"
    assert "delete_profile" not in api.calls and "delete_account" not in api.calls


def test_timeout_terminates_only_retained_owned_job_then_proves_exit(case):
    api = FakeNative(case[0])
    api.resume = lambda thread: api.calls.append("resume_without_exit")
    result = run(case, api)
    assert result["status"] == "FAILED_OR_UNSUPPORTED"
    assert result["cleanup_complete"] is True
    assert "terminate_job" in api.calls
    assert "terminate_suspended" not in api.calls


def test_invalid_child_token_is_stopped_before_resume(case):
    api = FakeNative(case[0])
    api.token = lambda process: token(PARENT, True)
    result = run(case, api)
    assert result["status"] == "FAILED_OR_UNSUPPORTED"
    assert result["cleanup_complete"]
    assert "resume" not in api.calls and "terminate_suspended" in api.calls


def test_job_assignment_failure_never_resumes(case):
    api = FakeNative(case[0], fail="job")
    run(case, api)
    assert "resume" not in api.calls and "terminate_suspended" in api.calls


@pytest.mark.parametrize("tamper", ["hash", "extra", "duplicate", "nonwheel"])
def test_input_manifest_is_bounded_exact_and_hash_verified(case, tamper):
    fixture, inputs, _ = case
    if tamper == "hash":
        inputs["wheel"]["sha256"] = "0" * 64
    elif tamper == "extra":
        inputs["unreviewed"] = True
    elif tamper == "duplicate":
        inputs["wheelhouse"].append(inputs["wheel"])
    else:
        inputs["wheel"] = inputs["python"]
    with pytest.raises(q.QualificationError):
        q.validate_inputs(inputs, fixture)


def test_environment_is_explicit_target_only_and_offline(case):
    fixture, _, _ = case
    profile = fixture.parent / "target-profile"
    env = q.target_environment(profile, fixture, fixture.parent / "Windows",
                               fixture.parent / "Python/python.exe")
    assert env["USERPROFILE"] == str(profile) and env["PIP_NO_INDEX"] == "1"
    assert not {"PASSWORD", "GITHUB_TOKEN", "PYTHONPATH", "PYTHONHOME"} & env.keys()
    assert env["PIP_FIND_LINKS"] == str(fixture / "input/wheels")


@pytest.mark.parametrize("tamper", ["file", "directory", "identity", "hash"])
def test_cleanup_refuses_foreign_changed_or_replaced_fixture(case, tamper):
    fixture = case[0]
    fixture.mkdir()
    (fixture / "owned").write_text("fixed")
    info = fixture.stat()
    identity = (info.st_dev, info.st_ino)
    expected = {"owned": q.digest(fixture / "owned")}
    if tamper == "file":
        (fixture / "foreign").write_text("retain")
    elif tamper == "directory":
        (fixture / "foreign").mkdir()
    elif tamper == "identity":
        identity = (info.st_dev, info.st_ino + 1)
    else:
        (fixture / "owned").write_text("changed")
    with pytest.raises(q.QualificationError):
        q.fixture_cleanup(fixture, identity, expected)
    assert (fixture / "owned").exists()


def test_reparse_ancestor_is_rejected_without_native_mutation(case, monkeypatch):
    fixture = case[0]
    original = Path.lstat
    def fake(path):
        if path == fixture.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=1024)
        return original(path)
    monkeypatch.setattr(Path, "lstat", fake)
    with pytest.raises(q.QualificationError, match="reparse_path"):
        q.safe_path(fixture, missing=True)


def test_native_launch_never_passes_password_through_argv_or_environment(case):
    fixture = case[0]
    api = object.__new__(native.Native)
    secret = ctypes.create_unicode_buffer("SYNTHETIC-memory-only-Aa1!")
    observed = {}
    def call(lib, name, result, types, *args):
        assert name == "CreateProcessWithLogonW"
        observed.update(logon_flags=args[3], application=args[4], command=args[5].value,
                        creation_flags=args[6], environment=args[7].value)
        assert args[2] is secret
        return 1
    api.call = call
    api.launch("dmqfixture", secret, [str(fixture.parent / "python.exe"), "-I", "-B", "fixed.py"],
               {"USERPROFILE": "C:\\Users\\synthetic"}, fixture.parent)
    assert observed["logon_flags"] == 1
    assert observed["creation_flags"] & 4  # suspended
    assert observed["creation_flags"] & 0x400  # Unicode environment
    assert secret.value not in json.dumps(observed)


def test_native_import_is_inert_and_no_netcredentials_path_exists():
    source = (ROOT / "tools/release/windows_standard_user_native.py").read_text()
    assert "LOGON_NETCREDENTIALS_ONLY" not in source
    assert "AdjustTokenPrivileges" not in source and "StartService" not in source
    assert native.Native.__init__ is not None


@pytest.mark.parametrize("fault", [None, "live_runtime", "held_lock", "offline", "package"])
def test_child_smoke_requires_exact_package_actual_exit_lock_and_offline(case, monkeypatch, fault):
    fixture, inputs, _env = case
    monkeypatch.setattr(q.sys, "executable", inputs["python"]["path"])
    api = FakeNative(fixture)
    api.profile.mkdir()
    (api.profile / "AppData/Local").mkdir(parents=True)
    q.prepare_fixture(fixture, q.validate_inputs(inputs, fixture), PARENT, SID, api, api.profile)
    child_env = q.target_environment(api.profile, fixture, fixture.parent / "Windows",
                                     Path(inputs["python"]["path"]))
    api.token = lambda process=None: token()
    api.loaded_profile = lambda sid: True
    api.runtime_handle = lambda port, sid, image: "retained-runtime"
    api.wait = lambda handle, timeout: fault != "live_runtime"
    api.exit_code = lambda handle: 0
    calls = []
    body = b"accepted package file"
    checker = SimpleNamespace()
    checker.inspect_archive = lambda wheel: {
        "members": {"decision_mesh/capture.py": q.hashlib.sha256(body).hexdigest()}
    }
    def fake_run(args, **kwargs):
        calls.append([str(a) for a in args])
        failed = fault == "held_lock" and "owner_file_lock" in " ".join(map(str, args))
        return SimpleNamespace(returncode=1 if failed else 0, stdout="", stderr="")
    monkeypatch.setattr(q.subprocess, "run", fake_run)
    monkeypatch.setattr(q, "load_exact", lambda *args: checker)
    def smoke(wheel, work):
        data = work / "user-data"
        data.mkdir(parents=True)
        package = work / "environment/Lib/site-packages/decision_mesh"
        package.mkdir(parents=True)
        (package / "capture.py").write_bytes(b"modified" if fault == "package" else body)
        (data / "runtime.json").write_text('{"port": 12345}')
        selected = dict(child_env)
        if fault == "offline":
            selected["PIP_NO_INDEX"] = "0"
        for args in (["python", "-m", "pip", "check"],
                     ["command", "setup", "--verify-local"], ["command", "stop"]):
            checker.subprocess.run(args, env=selected)
        return {"synthetic_smoke": True}
    checker.smoke_install = smoke
    if fault:
        with pytest.raises(q.QualificationError):
            q.child_smoke(fixture, api, child_env)
    else:
        result = q.child_smoke(fixture, api, child_env)
        assert result["runtime_exited"] and result["lifetime_lock_released"]
        assert result["installed_package_bytes_equal"]
    if fault == "offline":
        assert not calls


def test_profile_replacement_prevents_profile_and_account_deletion(case, monkeypatch):
    api = FakeNative(case[0])
    original_stat = Path.stat
    original_resume = api.resume
    def resume(thread):
        original_resume(thread)
        def changed(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == api.profile:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1)
            return info
        monkeypatch.setattr(Path, "stat", changed)
    api.resume = resume
    result = run(case, api)
    assert not result["cleanup_complete"]
    assert "delete_profile" not in api.calls and "delete_account" not in api.calls


def test_main_missing_guard_never_loads_adapter_and_redacts_exception(case, monkeypatch, capsys):
    fixture = case[0]
    monkeypatch.setattr(q.sys, "argv", ["helper", "--fixture-root", str(fixture)])
    monkeypatch.setattr(q, "load_exact", lambda *args: pytest.fail("adapter must remain unloaded"))
    assert q.main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "REFUSED_OR_FAILED"


@pytest.mark.parametrize("metadata", ["Name: synthetic\nRequires-Dist: dep @ https://example.invalid/dep.whl\n", None])
def test_wheelhouse_rejects_direct_url_and_missing_metadata(tmp_path, metadata):
    path = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("synthetic.dist-info/METADATA" if metadata else "other", metadata or "empty")
    with pytest.raises(q.QualificationError):
        q.offline_wheel(path)


def test_uncertain_account_creation_preserves_unproven_account(case):
    api = FakeNative(case[0])
    original = api.add_account
    def uncertain(name, password, marker):
        original(name, password, marker)
        raise RuntimeError("private failure")
    api.add_account = uncertain
    result = run(case, api)
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN"
    assert not result["cleanup_complete"] and "delete_account" not in api.calls

@pytest.mark.parametrize("state", ["replacement", "absent", "query_error"])
def test_account_change_during_profile_cleanup_refuses_deletion(case, state):
    api = FakeNative(case[0])
    original = api.delete_profile
    def change_after_profile(sid, profile):
        original(sid, profile)
        if state == "replacement":
            api.current.update(sid="S-1-5-21-999-999-999-999", comment="foreign")
        elif state == "absent":
            api.current = None
        else:
            api.fail = "account"
    api.delete_profile = change_after_profile
    result = run(case, api)
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN"
    assert result["cleanup_complete"] is False
    assert "delete_profile" in api.calls and "delete_account" not in api.calls
    assert case[0].exists() and api.password.value == ""
    assert "never-log" not in json.dumps(result)
    if state == "replacement":
        assert api.current["comment"] == "foreign"


@pytest.mark.parametrize("state", ["owned", "absent", "name", "sid", "comment", "query_error",
                                    "delete_error"])
def test_native_account_deletion_rechecks_identity_at_call_boundary(state):
    api = object.__new__(native.Native)  # No DLL initialization.
    expected = {"name": "dmqfixture", "sid": SID, "comment": "owned-marker"}
    events = []
    def query(name):
        events.append("query")
        assert name == expected["name"]
        if state == "query_error":
            raise native.NativeError("account_query_failed")
        if state == "absent":
            return None
        current = expected.copy()
        if state in current:
            current[state] = "foreign"
        return current
    def call(lib, name, result, types, *args):
        events.append("delete")
        assert (lib, name, result) == ("netapi32", "NetUserDel", native.W.DWORD)
        assert types == [native.W.LPCWSTR, native.W.LPCWSTR]
        assert args == (None, expected["name"])
        return 5 if state == "delete_error" else 0
    api.account, api.call = query, call
    if state == "owned":
        api.delete_account(expected["name"], expected_sid=SID, expected_marker=expected["comment"])
    else:
        with pytest.raises(native.NativeError):
            api.delete_account(expected["name"], expected_sid=SID, expected_marker=expected["comment"])
    assert events == (["query", "delete"] if state in {"owned", "delete_error"} else ["query"])
