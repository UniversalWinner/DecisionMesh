"""Safety tests only: fake WinAPI/process adapters and task-owned temporary files."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import socket
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
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


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
           "SYSTEMROOT": str(tmp_path / "windows")}
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
    diagnostic = staticmethod(native.Native.diagnostic)

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

    def delete_profile(self, sid, profile, *, owned_work=None):
        self.hit("delete_profile")
        assert sid == SID and profile == self.profile
        assert owned_work == profile / "AppData/Local" / self.fixture.name
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
    def change_after_profile(sid, profile, *, owned_work=None):
        original(sid, profile, owned_work=owned_work)
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


@pytest.mark.parametrize("fault,phase", [
    ("create", "profile_create"), ("path", "profile_path_validation"),
    ("identity", "profile_identity"), ("registry", "profile_registry_binding"),
    ("binding", "profile_registry_binding"),
])
def test_profile_failures_keep_original_and_cleanup_diagnostics(case, monkeypatch, fault, phase):
    api = FakeNative(case[0])
    secret = "PRIVATE-exception-args-password-path"
    original_safe = q.safe_path
    original_stat = Path.stat
    def create(name, sid):
        raise native.NativeError("new_profile_required")
    def safe(path, **kwargs):
        if path == api.profile:
            raise q.QualificationError("reparse_path")
        return original_safe(path, **kwargs)
    def stat_profile(path, **kwargs):
        if path == api.profile and kwargs.get("follow_symlinks", True):
            raise PermissionError(13, secret, secret)
        return original_stat(path, **kwargs)
    def registry(sid):
        raise PermissionError(13, secret, secret)
    def cleanup(sid, profile, *, owned_work=None):
        raise RuntimeError(secret)
    if fault == "create":
        api.create_profile = create
    elif fault == "path":
        monkeypatch.setattr(q, "safe_path", safe)
    elif fault == "identity":
        monkeypatch.setattr(Path, "stat", stat_profile)
    elif fault == "registry":
        api.profile_path, api.delete_profile = registry, cleanup
    else:
        api.profile_path = lambda sid: api.profile.parent / "different-profile"
    result = run(case, api)
    assert result["failed_phase"] == phase
    assert result["failure"]["code"] in {
        "new_profile_required", "reparse_path", "os_error", "profile_binding_mismatch"
    }
    if fault != "binding":
        assert result["cleanup_complete"] is False
        assert result["cleanup_failed_phase"] in {
            "cleanup_profile_proof", "cleanup_profile_path",
            "cleanup_profile_identity", "cleanup_profile_deletion",
        }
        assert set(result["cleanup_failure"]) >= {"code", "operation"}
        assert api.current is not None and "delete_account" not in api.calls
    assert secret not in json.dumps(result)
    assert api.password.value == ""


@pytest.mark.parametrize("code", [5, 6, None])
def test_registry_uncertainty_blocks_profile_deletion(case, monkeypatch, code):
    import sys
    error = OSError("PRIVATE-query-error")
    if code is not None:
        error.winerror = code
    def open_key(*args):
        raise error
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_USERS=1, OpenKey=open_key))
    api = object.__new__(native.Native)
    calls = []
    api.profile_path = lambda sid: case[0]
    api.call = lambda *args: calls.append(args) or 1
    with pytest.raises(native.NativeError):
        api.delete_profile(SID, case[0])
    assert not calls


@pytest.mark.parametrize("status", [0, 1, 0x80070005, 0x800700B7, 0x800706F7])
def test_create_profile_preserves_exact_hresult_and_documented_call_shape(case, monkeypatch, status):
    api = object.__new__(native.Native)
    def call(lib, name, result, types, *args):
        assert (lib, name, result) == ("userenv", "CreateProfile", ctypes.c_long)
        assert types == [native.W.LPCWSTR, native.W.LPCWSTR, native.W.LPWSTR, native.W.DWORD]
        assert args[:2] == (SID, "dmqfixture")
        assert args[3] == len(args[2]) == 260
        args[2].value = str(case[0])
        return ctypes.c_int32(status).value
    api.call = call
    monkeypatch.setattr(ctypes, "get_last_error", lambda: pytest.fail("HRESULT is the return value"))
    if status == 0:
        assert api.create_profile("dmqfixture", SID) == case[0]
    else:
        with pytest.raises(native.NativeError) as caught:
            api.create_profile("dmqfixture", SID)
        assert api.diagnostic(caught.value, "profile_create") == {
            "code": "new_profile_required", "operation": "CreateProfile", "hresult": status
        }


def test_profile_hresult_and_missing_cleanup_proof_are_both_retained(case):
    api = FakeNative(case[0])
    def create(name, sid):
        raise native.NativeError("new_profile_required", operation="CreateProfile",
                                 hresult=0x80070005)
    api.create_profile = create
    result = run(case, api)
    assert result["failure"] == {
        "code": "new_profile_required", "operation": "CreateProfile", "hresult": 0x80070005
    }
    assert result["cleanup_failure"] == {
        "code": "profile_cleanup_unproven", "operation": "cleanup_profile_proof"
    }
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN"
    assert api.current is not None and "delete_profile" not in api.calls
    assert "delete_account" not in api.calls


@pytest.mark.parametrize("winerror,errno,expected", [(2, 2, False), (3, 2, None), (None, 2, None)])
def test_only_explicit_registry_key_not_found_means_unloaded(monkeypatch, winerror, errno, expected):
    import sys
    error = OSError(errno, "PRIVATE-registry-args")
    if winerror is not None:
        error.winerror = winerror
    def open_key(*args):
        raise error
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_USERS=1, OpenKey=open_key))
    api = object.__new__(native.Native)
    if expected is False:
        assert api.loaded_profile(SID) is False
    else:
        with pytest.raises(native.NativeError) as caught:
            api.loaded_profile(SID)
        detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
        assert detail["code"] == "profile_hive_query_failed"
        assert detail["operation"] == "RegOpenKeyExW" and detail["errno"] == errno


@pytest.mark.parametrize("close_error", [False, True])
def test_open_hive_is_loaded_and_close_failure_never_proves_unloaded(monkeypatch, close_error):
    import sys
    class Key:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            if close_error:
                error = OSError("PRIVATE-close")
                error.winerror = 2
                raise error
    monkeypatch.setitem(sys.modules, "winreg",
                        SimpleNamespace(HKEY_USERS=1, OpenKey=lambda *args: Key()))
    api = object.__new__(native.Native)
    if close_error:
        with pytest.raises(OSError):
            api.loaded_profile(SID)
    else:
        assert api.loaded_profile(SID) is True


def test_delete_profile_captures_last_error_immediately_without_other_calls(case, monkeypatch):
    case[0].mkdir()
    api = object.__new__(native.Native)
    api.loaded_profile = lambda sid: False
    api.profile_path = lambda sid: case[0]
    events = []
    def call(lib, name, result, types, *args):
        events.append(name)
        assert (lib, name, result) == ("userenv", "DeleteProfileW", native.W.BOOL)
        assert args == (SID, str(case[0]), None)
        return 0
    def last_error():
        events.append("last_error")
        return 5
    api.call = call
    monkeypatch.setattr(ctypes, "get_last_error", last_error)
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, case[0])
    assert events == ["DeleteProfileW", "last_error"]
    assert api.diagnostic(caught.value, "cleanup_profile_deletion") == {
        "code": "profile_delete_failed", "operation": "DeleteProfileW", "winerror": 5
    }


@pytest.mark.parametrize("value", [-1, 2**32, True, "PRIVATE-numeric"])
def test_diagnostics_reject_unbounded_or_noninteger_native_status(value):
    error = native.NativeError("PRIVATE-code", operation="PRIVATE-operation",
                               hresult=value, winerror=value, errno=value)
    assert native.Native.diagnostic(error, "profile_create") == {
        "code": "unclassified_failure", "operation": "profile_create"
    }


def test_diagnostics_do_not_format_hostile_exceptions_or_project_arbitrary_attributes():
    class Hostile(RuntimeError):
        def __str__(self):
            raise AssertionError("Exception text must never be formatted")
        def __repr__(self):
            raise AssertionError("Exception args must never be formatted")
    error = Hostile("PRIVATE-args", {"path": "PRIVATE-profile", "password": "PRIVATE-password"})
    error.code, error.operation, error.hresult = "PRIVATE-code", "PRIVATE-operation", 5
    assert native.Native.diagnostic(error, "profile_identity") == {
        "code": "unclassified_failure", "operation": "profile_identity"
    }
    error = OSError(13, "PRIVATE-message", "PRIVATE-filename")
    error.winerror, error.hresult = 5, 99  # Only genuine OSError fields are projected.
    assert native.Native.diagnostic(error, "profile_identity") == {
        "code": "os_error", "operation": "profile_identity", "errno": 13, "winerror": 5
    }


@pytest.mark.parametrize("child", [False, True])
def test_main_and_child_failure_output_excludes_new_native_error_fields(case, monkeypatch, capsys, child):
    def fail(*args, **kwargs):
        raise native.NativeError("PRIVATE-code", operation="PRIVATE-op", hresult=5)
    args = ["helper", "--run-hosted", "--fixture-root", str(case[0])]
    if child:
        args.append("--child")
    monkeypatch.setattr(q.sys, "argv", args)
    monkeypatch.setattr(q, "runner_guard", lambda *args, **kwargs: None)
    monkeypatch.setattr(q, "load_exact", lambda *args: SimpleNamespace(
        Native=(lambda: FakeNative(case[0])) if child else fail))
    monkeypatch.setattr(q, "child_smoke", fail)
    assert q.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "REFUSED_OR_FAILED", "cleanup_complete": False
    }


@pytest.mark.parametrize("missing", [False, True])
def test_uppercase_windows_environment_launches_or_cleans_missing_root(case, missing):
    fixture, inputs, env = case
    assert "SystemRoot" not in env and all(key == key.upper() for key in env)
    api = FakeNative(fixture)
    original_launch = api.launch
    observed = {}
    def launch(name, password, argv, child_env, cwd):
        observed.update(child_env)
        return original_launch(name, password, argv, child_env, cwd)
    api.launch = launch
    if missing:
        del env["SYSTEMROOT"]
    result = run(case, api)
    assert result["cleanup_complete"] and api.current is None
    assert not fixture.exists() and not api.profile.exists() and api.password.value == ""
    if missing:
        assert result["status"] == "FAILED_OR_UNSUPPORTED"
        assert result["failed_phase"] == "fixture_staging"
        assert "launch" not in api.calls and not observed
    else:
        assert result["status"] == "PASS" and "launch" in api.calls
        root = Path(env["SYSTEMROOT"])
        assert observed["SystemRoot"] == observed["WINDIR"] == str(root)
        assert observed["COMSPEC"] == str(root / "System32/cmd.exe")
        assert observed["PATH"] == str(Path(inputs["python"]["path"]).parent) + q.os.pathsep + str(root / "System32")
        assert observed["USERPROFILE"] == str(api.profile)
        assert observed["PIP_NO_INDEX"] == "1"
        assert observed["PIP_FIND_LINKS"] == str(fixture / "input/wheels")


@pytest.fixture
def cleanup_observation(tmp_path, monkeypatch):
    """No DLLs, registry, process or actual waiting: only owned empty directories."""
    profile = tmp_path / "observation-profile"
    profile.mkdir()
    api = object.__new__(native.Native)
    state = {"registry": profile, "calls": [], "now": 0.0, "sleep": [], "tick": None}
    api.loaded_profile = lambda sid: False
    def registration(sid, *, missing=False):
        value = state["registry"]
        if isinstance(value, BaseException):
            raise value
        if value is None and not missing:
            error = FileNotFoundError(2, "synthetic missing key")
            error.winerror = 2
            raise error
        return value
    def call(lib, name, result, types, *args):
        assert (lib, name, args) == ("userenv", "DeleteProfileW", (SID, str(profile), None))
        state["calls"].append(name)
        if state.get("delete"):
            state["delete"]()
        return 1
    def sleep(seconds):
        assert 0 < seconds <= 0.05
        state["sleep"].append(seconds)
        state["now"] += seconds
        if state["tick"]:
            state["tick"]()
    api.profile_path, api.call = registration, call
    monkeypatch.setattr(native.time, "monotonic", lambda: state["now"])
    monkeypatch.setattr(native.time, "sleep", sleep)
    return api, profile, state


@pytest.mark.parametrize("delayed", [False, True])
def test_profile_cleanup_observation_waits_for_both_absences_once(cleanup_observation, delayed):
    api, profile, state = cleanup_observation
    def remove():
        profile.rmdir()
        state["registry"] = None
        state["tick"] = None
    if delayed:
        state["tick"] = lambda: remove() if state["now"] >= 0.15 else None
    else:
        state["delete"] = remove
    api.delete_profile(SID, profile)
    assert state["calls"] == ["DeleteProfileW"]
    assert bool(state["sleep"]) is delayed
    assert state["now"] < 1


@pytest.mark.parametrize("remaining", ["root", "registry", "both"])
def test_profile_cleanup_observation_deadline_keeps_uncertain_cleanup_failed(
        cleanup_observation, remaining):
    api, profile, state = cleanup_observation
    def remove_some():
        if remaining == "registry":
            profile.rmdir()
        if remaining == "root":
            state["registry"] = None
    state["delete"] = remove_some
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, profile)
    detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
    assert detail["residual"]["profile_root"]["state"] == (
        "absent" if remaining == "registry" else "present")
    assert detail["residual"]["profile_registry"]["state"] == (
        "absent" if remaining == "root" else "present")
    assert state["calls"] == ["DeleteProfileW"]
    assert 10 <= state["now"] <= 10.05 and len(state["sleep"]) <= 201


@pytest.mark.parametrize("fault", ["access", "registry", "binding", "identity", "reparse"])
def test_profile_cleanup_observation_rejects_errors_or_changed_identity_immediately(
        cleanup_observation, monkeypatch, fault):
    api, profile, state = cleanup_observation
    original = Path.lstat
    def altered(path, *args, **kwargs):
        if path == profile and state["calls"]:
            if fault == "access":
                raise PermissionError(13, "PRIVATE-root-path")
            info = original(path, *args, **kwargs)
            if fault in {"identity", "reparse"}:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1,
                                       st_mode=info.st_mode,
                                       st_file_attributes=1024 if fault == "reparse" else 0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", altered)
    def change():
        if fault == "registry":
            state["registry"] = PermissionError(13, "PRIVATE-registry")
        elif fault == "binding":
            state["registry"] = profile.parent / "PRIVATE-foreign-profile"
    state["delete"] = change
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, profile)
    detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
    assert detail["residual"]
    assert not state["sleep"] and state["calls"] == ["DeleteProfileW"]
    assert "PRIVATE" not in json.dumps(detail)


def test_profile_cleanup_residual_has_only_exact_fixture_locations(cleanup_observation):
    api, profile, _state = cleanup_observation
    work = profile / "AppData/Local" / ("decisionmesh-standard-user-" + NONCE)
    (work / "user-data").mkdir(parents=True)
    (work / "environment").mkdir()
    (profile / "PRIVATE-unrelated").mkdir()
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, profile, owned_work=work)
    detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
    assert detail["residual"] == {label: {"state": "present"} for label in (
        "profile_root", "profile_registry", "owned_work", "user_data", "environment")}
    assert str(profile) not in json.dumps(detail) and "PRIVATE" not in json.dumps(detail)


@pytest.mark.parametrize("location", ["AppData", "AppData/Local"])
def test_profile_cleanup_residual_does_not_query_below_replaced_ancestor(
        cleanup_observation, monkeypatch, location):
    api, profile, state = cleanup_observation
    work = profile / "AppData/Local" / ("decisionmesh-standard-user-" + NONCE)
    (work / "user-data").mkdir(parents=True)
    (work / "environment").mkdir()
    blocked = profile / location
    original = Path.lstat
    def altered(path, *args, **kwargs):
        if state["calls"]:
            assert not (path != blocked and path.is_relative_to(blocked)), "followed changed parent"
            if path == blocked:
                info = original(path, *args, **kwargs)
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1,
                                       st_mode=info.st_mode, st_file_attributes=0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", altered)
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, profile, owned_work=work)
    detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
    assert all(detail["residual"][label]["state"] == "query_error"
               for label in ("owned_work", "user_data", "environment"))


@pytest.mark.parametrize("order", ["root_first", "registry_first"])
def test_profile_cleanup_observes_both_absences_in_same_iteration(cleanup_observation, order):
    api, profile, state = cleanup_observation
    def tick():
        if state["now"] >= 0.05 and order == "root_first" and profile.exists():
            profile.rmdir()
        if state["now"] >= 0.05 and order == "registry_first":
            state["registry"] = None
        if state["now"] >= 0.15:
            if profile.exists():
                profile.rmdir()
            state["registry"] = None
    state["tick"] = tick
    api.delete_profile(SID, profile)
    assert 0.15 <= state["now"] < 0.2
    assert state["calls"] == ["DeleteProfileW"]


@pytest.mark.parametrize("fault", ["open_missing", "open_path_missing", "open_errno_only",
                                  "open_denied", "value_missing", "close_missing", "kind", "value"])
def test_profile_registration_absence_is_only_exact_key_open_not_found(monkeypatch, fault):
    import sys
    events = []
    def missing(code=2):
        error = FileNotFoundError(2, "PRIVATE-registry")
        if code is not None:
            error.winerror = code
        return error
    class Key:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            events.append("close")
            if fault == "close_missing":
                raise missing()
    def open_key(*args):
        events.append("open")
        if fault.startswith("open_"):
            raise missing({"open_missing": 2, "open_path_missing": 3,
                           "open_errno_only": None, "open_denied": 5}[fault])
        return Key()
    def query(*args):
        events.append("query")
        if fault == "value_missing":
            raise missing()
        return (123 if fault == "value" else "C:/synthetic-profile",
                999 if fault == "kind" else 1)
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        HKEY_LOCAL_MACHINE=1, REG_SZ=1, REG_EXPAND_SZ=2, OpenKey=open_key, QueryValueEx=query))
    api = object.__new__(native.Native)
    if fault == "open_missing":
        assert api.profile_path(SID, missing=True) is None
        assert events == ["open"]
    else:
        with pytest.raises((OSError, native.NativeError)):
            api.profile_path(SID, missing=True)
    assert events == (["open"] if fault.startswith("open_") else ["open", "query", "close"])


@pytest.mark.parametrize("mutation", ["reparse", "identity", "denied"])
def test_profile_cleanup_residual_checks_root_before_any_descendant(
        cleanup_observation, monkeypatch, mutation):
    api, profile, state = cleanup_observation
    work = profile / "AppData/Local" / ("decisionmesh-standard-user-" + NONCE)
    (work / "user-data").mkdir(parents=True)
    original = Path.lstat
    def altered(path, *args, **kwargs):
        if state["calls"]:
            assert not (path != profile and path.is_relative_to(profile)), "followed changed root"
            if path == profile:
                if mutation == "denied":
                    raise PermissionError(13, "PRIVATE-root")
                info = original(path, *args, **kwargs)
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1,
                                       st_mode=info.st_mode,
                                       st_file_attributes=1024 if mutation == "reparse" else 0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", altered)
    with pytest.raises(native.NativeError) as caught:
        api.delete_profile(SID, profile, owned_work=work)
    detail = api.diagnostic(caught.value, "cleanup_profile_deletion")
    assert all(detail["residual"][label]["state"] == "query_error"
               for label in ("profile_root", "owned_work", "user_data", "environment"))
    assert not state["sleep"]


@pytest.mark.parametrize("fault", ["outside", "nonfixture", "traversal"])
def test_profile_cleanup_rejects_unowned_diagnostic_location_before_delete(
        cleanup_observation, fault):
    api, profile, state = cleanup_observation
    work = {"outside": profile.parent / ("decisionmesh-standard-user-" + NONCE),
            "nonfixture": profile / "AppData/Local/PRIVATE-existing-data",
            "traversal": profile / "AppData/Local/../PRIVATE"}[fault]
    with pytest.raises(native.NativeError):
        api.delete_profile(SID, profile, owned_work=work)
    assert not state["calls"]


def test_profile_cleanup_residual_serialization_ignores_hostile_or_unrecognized_data():
    class Hostile:
        def __str__(self):
            raise AssertionError("never format")
        def __eq__(self, other):
            raise AssertionError("never compare")
    class HostileDict(dict):
        def get(self, *args):
            raise AssertionError("never inspect subclass")
    error = native.NativeError("profile_delete_not_observed", residual={
        "profile_root": {"state": "query_error", "winerror": 5, "errno": 13,
                         "path": "PRIVATE", "name": Hostile(), "content": "PRIVATE"},
        "profile_registry": {"state": Hostile()},
        "owned_work": {"state": "present", "winerror": True, "errno": -1},
        "user_data": HostileDict(state="present"),
        "environment": {"state": "absent", "winerror": 2**32, "errno": "PRIVATE"},
        "PRIVATE-discovered": {"state": "present"},
    })
    detail = native.Native.diagnostic(error, "cleanup_profile_deletion")
    assert detail["residual"] == {
        "profile_root": {"state": "query_error", "winerror": 5, "errno": 13},
        "owned_work": {"state": "present"}, "environment": {"state": "absent"}}
    assert "PRIVATE" not in json.dumps(detail)
    error.residual = HostileDict(profile_root={"state": "present"})
    assert "residual" not in native.Native.diagnostic(error, "cleanup_profile_deletion")
    error = RuntimeError("PRIVATE")
    error.residual = {"profile_root": {"state": "present"}}
    assert "residual" not in native.Native.diagnostic(error, "cleanup_profile_deletion")


def test_profile_cleanup_residual_ignores_hostile_key_comparisons():
    class HostileKey:
        def __hash__(self):
            return hash("profile_root")
        def __eq__(self, other):
            raise AssertionError("untrusted equality")
    error = native.NativeError("profile_delete_not_observed", residual={HostileKey(): "PRIVATE"})
    assert "residual" not in native.Native.diagnostic(error, "cleanup_profile_deletion")


@pytest.mark.parametrize("fault", ["persistent", "denied", "binding"])
def test_profile_observation_uncertainty_preserves_account_and_fixture(case, monkeypatch, fault):
    api = FakeNative(case[0])
    api.delete_profile = native.Native.delete_profile.__get__(api)
    api.loaded_profile = lambda sid: False
    called = []
    def registration(sid, *, missing=False):
        if missing and fault == "denied":
            raise PermissionError(13, "PRIVATE-registry")
        if missing and fault == "binding":
            return api.profile.parent / "PRIVATE-foreign"
        return api.profile
    def call(lib, name, *args):
        assert name == "DeleteProfileW", "account deletion must not be reached"
        called.append(name)
        return 1
    api.profile_path, api.call = registration, call
    clock = [0.0]
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    result = run(case, api)
    assert result["child"]["status"] == "PASS"
    assert result["status"] == "FAILED_CLEANUP_UNPROVEN" and not result["cleanup_complete"]
    assert result["cleanup_failed_phase"] == "cleanup_profile_deletion"
    assert result["cleanup_failure"]["residual"]
    assert api.current is not None and case[0].exists() and api.password.value == ""
    assert called == ["DeleteProfileW"] and "PRIVATE" not in json.dumps(result)


def test_optional_residual_baseline_cannot_hide_root_replacement_before_delete(
        cleanup_observation, monkeypatch):
    api, profile, state = cleanup_observation
    work = profile / "AppData/Local" / ("decisionmesh-standard-user-" + NONCE)
    (work / "user-data").mkdir(parents=True)
    original, root_reads = Path.lstat, []
    def changed(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == profile:
            root_reads.append(path)
            if len(root_reads) > 1:
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1,
                                       st_mode=info.st_mode, st_file_attributes=0)
        return info
    monkeypatch.setattr(Path, "lstat", changed)
    with pytest.raises(native.NativeError):
        api.delete_profile(SID, profile, owned_work=work)
    assert not state["calls"], "replacement discovered before deletion must prevent deletion"
