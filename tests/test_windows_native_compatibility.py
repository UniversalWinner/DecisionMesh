"""Sanitized Windows Scheduler compatibility fixtures; no account/path from a real run."""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from decision_mesh import windows_native as native
from decision_mesh import windows_task_read as task_read

SID = "S-1-5-21-100-200-300-1001"
ACCOUNT = "FIXTURE-PC\\fixture-user"
NS = {"t": native.TASK_NS}


@pytest.fixture
def synthetic_mutations(monkeypatch, tmp_path):
    """Run production mutation ordering with no real native/task/shortcut call."""
    def forbidden(*args, **kwargs):
        raise AssertionError("native mutation boundary forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(ctypes, "OleDLL", forbidden, raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", forbidden, raising=False)
    monkeypatch.setattr(native, "assert_owner_only", lambda path: None)
    monkeypatch.setattr(native, "atomic_write_owner_only", lambda path, body, **kw: Path(path).write_bytes(body))
    backend = object.__new__(native.NativeWindowsBackend)
    backend.data_dir = tmp_path
    state, calls = {"task": None}, []
    monkeypatch.setattr(backend, "read_task", lambda name: state["task"])
    monkeypatch.setattr(backend, "_run", lambda args: calls.append(args) or subprocess.CompletedProcess(args, 0))

    def link(path, value=None):
        if value is not None:
            path.write_text(json.dumps(asdict(value)), encoding="utf-8")
        else:
            return replace(native.ShortcutSpec(**json.loads(path.read_text(encoding="utf-8"))), path=str(path))
    monkeypatch.setattr(native, "_shell_link", link)
    return backend, state, calls, link


@pytest.mark.parametrize("replacing", [False, True])
def test_native_task_rechecks_after_xml_preparation(synthetic_mutations, monkeypatch, replacing):
    backend, state, calls, _ = synthetic_mutations
    prior = spec() if replacing else None
    state["task"] = prior
    edited = replace(spec(), arguments="ordinary editor changed this")
    original = native.atomic_write_owner_only
    def write(path, body, **kw):
        original(path, body, **kw)
        state["task"] = edited
    monkeypatch.setattr(native, "atomic_write_owner_only", write)
    with pytest.raises(native.IntegrationError, match="preserved"):
        backend.write_task(spec(), replace=replacing, expected=prior)
    assert state["task"] == edited and not calls
    assert not list(backend.data_dir.glob("task-*.xml"))


@pytest.mark.parametrize("operation", ["replace", "remove"])
def test_native_destructive_task_requires_exact_expected(synthetic_mutations, operation):
    backend, state, calls, _ = synthetic_mutations
    state["task"] = spec()
    with pytest.raises(native.IntegrationError, match="expected_state_required"):
        if operation == "replace":
            backend.write_task(spec(), replace=True)
        else:
            backend.remove_task(spec().name, expected=None)
    assert not calls


@pytest.mark.parametrize("kind", ["task", "shortcut"])
def test_native_removal_preserves_changed_spec(synthetic_mutations, tmp_path, kind):
    backend, state, calls, link = synthetic_mutations
    if kind == "task":
        prior = spec()
        state["task"] = replace(prior, arguments="edited")
        with pytest.raises(native.IntegrationError, match="preserved"):
            backend.remove_task(prior.name, expected=prior)
        assert state["task"].arguments == "edited" and not calls
    else:
        path = tmp_path / "Decision Mesh.lnk"
        prior = native.ShortcutSpec(str(path), "owner", "target", "prior")
        link(path, replace(prior, arguments="edited"))
        before = path.read_bytes()
        with pytest.raises(native.IntegrationError, match="preserved"):
            backend.remove_shortcut(path, expected=prior)
        assert path.read_bytes() == before


@pytest.mark.parametrize("boundary", ["staging", "publication"])
def test_new_shortcut_cannot_clobber_newly_appeared_destination(
    synthetic_mutations, monkeypatch, tmp_path, boundary
):
    backend, _, _, shell_link = synthetic_mutations
    path = tmp_path / "Decision Mesh.lnk"
    desired = native.ShortcutSpec(str(path), "owner", "target", "desired")
    editor = replace(desired, arguments="ordinary editor")
    original_link = native.os.link
    if boundary == "staging":
        def stage(temporary, value=None):
            result = shell_link(temporary, value)
            if value is not None:
                shell_link(path, editor)
            return result
        monkeypatch.setattr(native, "_shell_link", stage)
    else:
        def publish(source, destination):
            shell_link(path, editor)
            return original_link(source, destination)
        monkeypatch.setattr(native.os, "link", publish)
    with pytest.raises((native.IntegrationError, FileExistsError)):
        backend.write_shortcut(desired)
    assert backend.read_shortcut(path) == editor
    assert not list(tmp_path.glob(".decisionmesh-*"))


@pytest.mark.parametrize("edited", [False, True])
def test_shortcut_replacement_checks_after_staging(synthetic_mutations, monkeypatch, tmp_path, edited):
    backend, _, _, shell_link = synthetic_mutations
    path = tmp_path / "Decision Mesh.lnk"
    prior = native.ShortcutSpec(str(path), "owner", "target", "prior")
    desired, editor = replace(prior, arguments="desired"), replace(prior, arguments="editor")
    shell_link(path, prior)
    def stage(temporary, value=None):
        result = shell_link(temporary, value)
        if value is not None and edited:
            shell_link(path, editor)
        return result
    monkeypatch.setattr(native, "_shell_link", stage)
    if edited:
        with pytest.raises(native.IntegrationError, match="preserved"):
            backend.write_shortcut(desired, expected=prior)
    else:
        backend.write_shortcut(desired, expected=prior)
    assert backend.read_shortcut(path) == (editor if edited else desired)
    assert not list(tmp_path.glob(".decisionmesh-*"))


def test_native_shortcut_exclusive_create_and_owned_remove_control(synthetic_mutations, tmp_path):
    backend, _, _, _ = synthetic_mutations
    path = tmp_path / "Decision Mesh.lnk"
    desired = native.ShortcutSpec(str(path), "owner", "target", "desired")
    backend.write_shortcut(desired)
    assert backend.read_shortcut(path) == desired
    with pytest.raises(native.IntegrationError, match="preserved"):
        backend.write_shortcut(replace(desired, arguments="another install"))
    assert backend.read_shortcut(path) == desired
    backend.remove_shortcut(path, expected=desired)
    assert not path.exists() and not list(tmp_path.glob(".decisionmesh-*"))


def spec(*, unicode=False):
    folder = "owned-\u0928\u092e\u0938\u094d\u0924\u0947" if unicode else "owned-fixture"
    return native.TaskSpec("DecisionMesh-synthetic", "DecisionMesh/v1/synthetic", SID,
                           "C:\\Windows\\System32\\wscript.exe", f'//B //Nologo "C:\\{folder}\\noop.vbs"')


def scheduler_document(value, *, account=SID):
    root = ET.fromstring(native.task_xml(value))
    for parent, child in (
        ("t:Triggers/t:LogonTrigger", "Enabled"),
        ("t:Principals/t:Principal", "RunLevel"),
        ("t:Settings", "Enabled"),
    ):
        node = root.find(parent, NS)
        node.remove(node.find("t:" + child, NS))
    root.find("t:Triggers/t:LogonTrigger/t:UserId", NS).text = account
    ET.SubElement(root.find("t:RegistrationInfo", NS), "{" + native.TASK_NS + "}URI").text = "\\" + value.name
    idle = ET.SubElement(root.find("t:Settings", NS), "{" + native.TASK_NS + "}IdleSettings")
    ET.SubElement(idle, "{" + native.TASK_NS + "}StopOnIdleEnd").text = "true"
    ET.SubElement(idle, "{" + native.TASK_NS + "}RestartOnIdle").text = "false"
    groups = {node.tag.rsplit("}", 1)[-1]: node for node in root}
    root[:] = [groups[name] for name in ("RegistrationInfo", "Principals", "Settings", "Triggers", "Actions")]
    settings = root.find("t:Settings", NS)
    settings[:] = sorted(settings, key=lambda node: node.tag)
    return "<?xml version='1.0' encoding='utf-16'?>\n" + ET.tostring(root, encoding="unicode")


def test_observed_scheduler_defaults_and_order_are_equivalent():
    value = spec()
    assert native.parse_task(value.name, scheduler_document(value).encode("utf-16")) == value


def test_unicode_document_retains_exact_paths():
    value = spec(unicode=True)
    assert native.parse_task(value.name, scheduler_document(value)) == value


def test_legacy_schtasks_encoding_mismatch_is_not_guessed():
    value = spec()
    raw = scheduler_document(value).encode("ascii")
    with pytest.raises(native.IntegrationError):
        native.parse_task(value.name, raw)


@pytest.mark.parametrize("account", [ACCOUNT, ACCOUNT.lower(), "FIXTURE-PC\\\u540d\u524d"])
def test_alias_only_uses_verified_current_sid_and_account(account):
    value = spec(unicode=True)
    document = scheduler_document(value, account=account)
    identity = (SID, ACCOUNT if account.isascii() else account)
    assert native.parse_task(value.name, document, current_identity=identity) == value


@pytest.mark.parametrize("identity", [None, ("S-1-5-21-9-8-7-1001", ACCOUNT), (SID, "OTHER\\user")])
def test_alias_without_exact_current_identity_is_refused(identity):
    with pytest.raises(native.IntegrationError):
        native.parse_task(spec().name, scheduler_document(spec(), account=ACCOUNT), current_identity=identity)


@pytest.mark.parametrize("alias,account", [("PC\\STRASSE", "PC\\Stra\u00dfe"), ("PC\\\u00c4", "PC\\\u00e4")])
def test_unqualified_unicode_case_aliases_are_refused(alias, account):
    with pytest.raises(native.IntegrationError):
        native.parse_task(spec().name, scheduler_document(spec(), account=alias), current_identity=(SID, account))


@pytest.mark.parametrize("change", [
    "disabled_trigger", "disabled_task", "elevated", "idle_stop", "idle_restart", "unknown_setting",
    "uri", "duplicate_uri", "duplicate_idle", "trigger_user", "principal", "extra_action",
    "working_directory", "repetition", "extra_attribute", "mixed_text",
])
def test_observed_serialization_does_not_hide_tampering(change):
    value = spec()
    root = ET.fromstring(scheduler_document(value))
    tag = lambda name: "{" + native.TASK_NS + "}" + name
    def node(path):
        return root.find(path, NS)
    if change in {"disabled_trigger", "disabled_task", "elevated"}:
        path, field, text = {
            "disabled_trigger": ("t:Triggers/t:LogonTrigger", "Enabled", "false"),
            "disabled_task": ("t:Settings", "Enabled", "false"),
            "elevated": ("t:Principals/t:Principal", "RunLevel", "HighestAvailable"),
        }[change]
        ET.SubElement(node(path), tag(field)).text = text
    elif change.startswith("idle_"):
        node("t:Settings/t:IdleSettings/t:" + ("StopOnIdleEnd" if change == "idle_stop" else "RestartOnIdle")).text = "false" if change == "idle_stop" else "true"
    elif change == "unknown_setting":
        ET.SubElement(node("t:Settings"), tag("WakeToRun")).text = "true"
    elif change == "uri":
        node("t:RegistrationInfo/t:URI").text = "\\ForeignTask"
    elif change in {"duplicate_uri", "duplicate_idle"}:
        path, child = ("t:RegistrationInfo", "URI") if change == "duplicate_uri" else ("t:Settings", "IdleSettings")
        node(path).append(ET.fromstring(ET.tostring(node(path + "/t:" + child))))
    elif change == "trigger_user":
        node("t:Triggers/t:LogonTrigger/t:UserId").text = "OTHER\\user"
    elif change == "principal":
        node("t:Principals/t:Principal/t:UserId").text = "S-1-5-21-9-8-7-1001"
    elif change == "extra_action":
        node("t:Actions").append(ET.fromstring(ET.tostring(node("t:Actions/t:Exec"))))
    elif change == "working_directory":
        ET.SubElement(node("t:Actions/t:Exec"), tag("WorkingDirectory")).text = "C:\\other"
    elif change == "repetition":
        ET.SubElement(node("t:Triggers/t:LogonTrigger"), tag("Repetition"))
    elif change == "extra_attribute":
        node("t:Settings/t:IdleSettings").set("unexpected", "true")
    else:
        node("t:Settings/t:IdleSettings").text = "unexpected"
    with pytest.raises(native.IntegrationError):
        native.parse_task(value.name, ET.tostring(root, encoding="unicode"), current_identity=(SID, ACCOUNT))


def test_changed_action_is_not_equal_to_owned_spec():
    value = spec()
    root = ET.fromstring(scheduler_document(value))
    root.find("t:Actions/t:Exec/t:Arguments", NS).text = "different"
    assert native.parse_task(value.name, ET.tostring(root, encoding="unicode")) != value


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_dtd_is_rejected_before_xml_expansion(encoding):
    raw = '<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY test "text">]><Task/>'.encode(encoding)
    with pytest.raises(native.IntegrationError):
        native.parse_task(spec().name, raw)


def test_native_backend_reads_unicode_and_binds_current_identity(monkeypatch):
    value = spec(unicode=True)
    monkeypatch.setattr(native, "read_task_document", lambda name: (scheduler_document(value, account=ACCOUNT.lower()), ACCOUNT))
    monkeypatch.setattr(native, "current_user_sid", lambda: SID)
    backend = object.__new__(native.NativeWindowsBackend)
    backend._run = lambda args: pytest.fail("legacy code-page query must not be used")
    assert backend.read_task(value.name) == value


def test_native_backend_absence_does_not_lookup_account(monkeypatch):
    monkeypatch.setattr(native, "read_task_document", lambda name: None)
    monkeypatch.setattr(native, "current_user_sid", lambda: pytest.fail("absent task has no identity"))
    assert object.__new__(native.NativeWindowsBackend).read_task(spec().name) is None


def test_native_backend_query_errors_fail_closed(monkeypatch):
    def fail(name):
        raise task_read.TaskReadError("query_failed")
    monkeypatch.setattr(native, "read_task_document", fail)
    with pytest.raises(native.IntegrationError, match="windows_task_query_failed"):
        object.__new__(native.NativeWindowsBackend).read_task(spec().name)


@pytest.mark.parametrize("mode", ["ok", "absent", "error", "nonascii", "too_large", "timeout", "exit", "wrong_schema"])
def test_unicode_ipc_transport_is_strict_bounded_and_hidden(monkeypatch, mode):
    value = spec(unicode=True)
    calls = []
    reply = {"status": "present", "xml": scheduler_document(value), "account": ACCOUNT}
    if mode in {"absent", "error"}:
        reply = {"status": mode}
    if mode == "wrong_schema":
        reply["unexpected"] = True
    output = json.dumps(reply, ensure_ascii=True).encode("ascii")
    if mode == "nonascii":
        output = b"\xff"
    if mode == "too_large":
        output = b" " * (task_read.MAX_REPLY_BYTES + 1)
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if mode == "timeout":
            raise subprocess.TimeoutExpired(argv, 15)
        return subprocess.CompletedProcess(argv, 1 if mode == "exit" else 0, output, b"")
    monkeypatch.setattr(task_read.subprocess, "run", run)
    if mode == "ok":
        xml, account = task_read.read_task_document(value.name)
        assert xml == reply["xml"] and account == ACCOUNT
    elif mode == "absent":
        assert task_read.read_task_document(value.name) is None
    else:
        with pytest.raises(task_read.TaskReadError, match="query_failed"):
            task_read.read_task_document(value.name)
    argv, options = calls[0]
    assert argv[1:4] == ["-I", "-B", "-c"] and argv[-1] == value.name
    assert options["timeout"] == 15 and options["shell"] is False
    assert options["creationflags"] == subprocess.CREATE_NO_WINDOW


@pytest.mark.parametrize("name", ["", "\\Foreign\\Task", "..", "task*", "task?", "task\x00other"])
def test_query_does_not_allow_paths_or_wildcards(name):
    with pytest.raises(task_read.TaskReadError, match="name_invalid"):
        task_read.read_task_document(name)


@pytest.mark.parametrize("failure", [None, "Connect", "GetFolder", "GetTask", "Xml", "absent"])
def test_com_query_releases_every_acquired_reference(monkeypatch, failure):
    calls, released = [], []
    class Ole:
        def CoInitializeEx(self, pointer, flags):
            calls.append(("initialize", flags))
            return 0
        def CoCreateInstance(self, clsid, outer, flags, iid, output):
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(101)
            return 0
        def CoUninitialize(self):
            calls.append(("uninitialize",))
    class Dispatch:
        ole = Ole()
        def invoke(self, pointer, member, args=(), *, kind="empty"):
            calls.append((member, args))
            if member == failure:
                raise task_read._ComFailure(0x80070005)
            if member == "GetTask" and failure == "absent":
                raise task_read._ComFailure(0x80070002)
            return {"Connect": None, "GetFolder": ctypes.c_void_p(102),
                    "GetTask": ctypes.c_void_p(103), "Xml": scheduler_document(spec(unicode=True))}[member]
    monkeypatch.setattr(task_read, "_Dispatch", Dispatch)
    monkeypatch.setattr(task_read, "_call", lambda pointer, slot, types: released.append(pointer.value))
    monkeypatch.setattr(task_read, "_current_account", lambda: ACCOUNT)
    if failure is None:
        assert task_read._query_local(spec().name)[1] == ACCOUNT
    elif failure == "absent":
        assert task_read._query_local(spec().name) is None
    else:
        with pytest.raises(task_read._ComFailure):
            task_read._query_local(spec().name)
    expected = [101] if failure in {"Connect", "GetFolder"} else [102, 101] if failure in {"GetTask", "absent"} else [103, 102, 101]
    assert released == expected and calls[-1] == ("uninitialize",)
    assert ("Connect", ()) in calls
    if failure != "Connect":
        assert ("GetFolder", ("\\",)) in calls


def test_variant_abi_size_matches_windows_architecture():
    assert ctypes.sizeof(task_read._Variant) == (24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16)


@pytest.mark.parametrize("layout", [
    "source", "installed", "zip", "namespace_directory", "zip_without_init",
    "missing_origin", "missing_module", "invalid_archive", "missing_zip_module",
    "duplicate_zip_member", "oversized_directory", "oversized_zip",
])
def test_isolated_child_enforces_exact_directory_or_zip_origin(monkeypatch, tmp_path, layout):
    import zipfile
    from pathlib import Path
    captured = []
    real_run = subprocess.run
    def capture(argv, **kwargs):
        captured.append(argv)
        return subprocess.CompletedProcess(argv, 0, b'{"status":"absent"}', b"")
    monkeypatch.setattr(task_read.subprocess, "run", capture)
    assert task_read.read_task_document("DecisionMesh-synthetic") is None
    code = captured[0][4]
    source = 'import json\ndef _main(name): print(json.dumps({"status":"origin_ok","origin":__file__}))\n'
    package_marker = tmp_path / "trusted-package-executed"
    alternate_package_marker = tmp_path / "alternate-package-executed"
    alternate_module_marker = tmp_path / "alternate-module-executed"
    def marker_source(path):
        return "from pathlib import Path\nPath(" + repr(str(path)) + ").write_text('executed')\n"
    alternate = tmp_path / "alternate-install"
    alternate_package = alternate / "decision_mesh"
    alternate_package.mkdir(parents=True)
    (alternate_package / "__init__.py").write_text(marker_source(alternate_package_marker), encoding="utf-8")
    (alternate_package / "windows_task_read.py").write_text(
        marker_source(alternate_module_marker) + source, encoding="utf-8")
    # Model an otherwise importable installed copy, as in the independent F1 repro.
    code = "import sys;sys.path.insert(0," + repr(str(alternate)) + ")\n" + code
    origin = tmp_path / ("src" if layout == "source" else "site-packages")
    package = origin / "decision_mesh"
    package.mkdir(parents=True)
    if layout != "namespace_directory":
        (package / "__init__.py").write_text(marker_source(package_marker), encoding="utf-8")
    if layout != "missing_module":
        (package / "windows_task_read.py").write_text(
            source + ("#" * 131073 if layout == "oversized_directory" else ""), encoding="utf-8")
    if layout in {"zip", "zip_without_init", "missing_zip_module", "duplicate_zip_member", "oversized_zip"}:
        origin = tmp_path / "reader-fixture.zip"
        with zipfile.ZipFile(origin, "w") as archive:
            if layout != "zip_without_init":
                archive.writestr("decision_mesh/__init__.py", marker_source(package_marker))
            if layout != "missing_zip_module":
                archive.writestr("decision_mesh/windows_task_read.py",
                                 source + ("#" * 131073 if layout == "oversized_zip" else ""))
            if layout == "duplicate_zip_member":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    archive.writestr("decision_mesh/windows_task_read.py", source)
    elif layout == "missing_origin":
        origin = tmp_path / "missing-package-root"
    elif layout == "invalid_archive":
        origin = tmp_path / "invalid.zip"
        origin.write_text("not a ZIP", encoding="utf-8")
    result = real_run([sys.executable, "-I", "-B", "-c", code, str(origin), "DecisionMesh-synthetic"],
                      capture_output=True, timeout=15, check=False, shell=False,
                      creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0 and result.stderr == b""
    reply = json.loads(result.stdout)
    # Check effects, not merely the fixed final error: import-time code cannot run.
    assert not alternate_package_marker.exists()
    assert not alternate_module_marker.exists()
    assert not package_marker.exists()
    if layout in {"source", "installed", "zip", "namespace_directory", "zip_without_init"}:
        assert reply["status"] == "origin_ok"
        assert Path(reply["origin"]).resolve() == (origin / "decision_mesh/windows_task_read.py").resolve()
    else:
        assert reply == {"status": "error"}


@pytest.mark.parametrize("mode", ["unicode", "dispatch", "exception"])
def test_com_invoke_clears_variants_and_exception_bstrs(monkeypatch, mode):
    buffers, cleared, freed = [], [], []
    text = "Task-\u540d\u524d-\u0928\u092e\u0938\u094d\u0924\u0947"
    output = ctypes.create_unicode_buffer(text)
    buffers.append(output)
    class Auto:
        def SysAllocString(self, value):
            buffer = ctypes.create_unicode_buffer(value)
            buffers.append(buffer)
            return ctypes.addressof(buffer)
        def VariantClear(self, pointer):
            value = ctypes.cast(pointer, ctypes.POINTER(task_read._Variant)).contents
            cleared.append(value.vt)
            value.vt = 0
        def SysFreeString(self, pointer):
            freed.append(pointer)
        def SysStringLen(self, pointer):
            return len(text.encode("utf-16-le")) // 2
    def call(pointer, slot, types, *args):
        if slot == 5:
            return 0
        result = ctypes.cast(args[5], ctypes.POINTER(task_read._Variant)).contents
        error = ctypes.cast(args[6], ctypes.POINTER(task_read._ExceptionInfo)).contents
        if mode == "exception":
            error.scode = ctypes.c_int32(0x80070002).value
            error.source = 701
            error.description = 702
            error.helpfile = 703
            return ctypes.c_int32(0x80020009).value
        result.vt = 8 if mode == "unicode" else 9
        result.pointer = ctypes.addressof(output) if mode == "unicode" else 704
        return 0
    monkeypatch.setattr(task_read, "_call", call)
    dispatch = object.__new__(task_read._Dispatch)
    dispatch.auto = Auto()
    if mode == "exception":
        with pytest.raises(task_read._ComFailure) as caught:
            dispatch.invoke(ctypes.c_void_p(1), "GetTask", ("synthetic",), kind="dispatch")
        assert caught.value.code == 0x80070002 and freed == [701, 702, 703]
    else:
        result = dispatch.invoke(ctypes.c_void_p(1), "Xml" if mode == "unicode" else "GetTask",
                                 ("synthetic",), kind="text" if mode == "unicode" else "dispatch")
        assert result == text if mode == "unicode" else result.value == 704
    assert cleared == [8, 8 if mode == "unicode" else 0]
