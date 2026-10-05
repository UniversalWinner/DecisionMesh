from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from decision_mesh import capture


def envelope():
    return {
        "schema_version": 1,
        "producer_id": "test-explicit",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "event_kind": "observation.recorded",
        "source_request_id": None,
        "revision": None,
        "occurred_at": None,
        "captured_at": "2026-10-04T00:00:00Z",
        "source_context": {"producer_kind": "explicit"},
        "evidence_class": "producer_reported",
        "capture_policy_ref": None,
        "payload": {"snapshot": {"kind": "question", "title": "Synthetic qualification"}},
    }


def invoke(spool, raw):
    return subprocess.run(
        [sys.executable, "-m", "decision_mesh.capture", "--spool", str(spool)],
        input=raw,
        capture_output=True,
        check=False,
        timeout=10,
    )


def secure_file(path, text):
    path.write_text(text, encoding="utf-8")
    capture._protect_new(path)
    return path


def file_security_state(path):
    """Read exact owner/DACL (or POSIX ownership/mode) without changing it."""
    if os.name != "nt":
        info = path.stat()
        return info.st_uid, info.st_mode

    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    needed = wintypes.DWORD()
    advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
    descriptor = ctypes.create_string_buffer(needed.value)
    assert advapi.GetFileSecurityW(str(path), 5, descriptor, needed.value, ctypes.byref(needed))
    return descriptor.raw


def insecure_file(path, raw):
    """Exclusively create a current-user-owned file with a deliberately invalid ACL."""
    if os.name != "nt":
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o644)
    else:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL),
            ]

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        sid = capture._windows_sid()
        descriptor = ctypes.c_void_p()
        # Fix identity at creation; deliberately omit P from the sole-user
        # DACL. Never repair an existing or foreign-owned fixture.
        assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{sid}D:(A;;FA;;;{sid})", 1, ctypes.byref(descriptor), None
        )
        try:
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            handle = kernel.CreateFileW(
                str(path), 0x40000000, 3, ctypes.byref(attributes), 1, 128, None
            )
            assert handle != wintypes.HANDLE(-1).value
        finally:
            kernel.LocalFree(descriptor)
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)

        # Independently establish the native owner/unprotected-DACL precondition.
        actual = ctypes.create_string_buffer(file_security_state(path))
        advapi.GetSecurityDescriptorOwner.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
        ]
        advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
        ]
        owner = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        assert advapi.GetSecurityDescriptorOwner(actual, ctypes.byref(owner), ctypes.byref(defaulted))
        owner_text = wintypes.LPWSTR()
        assert advapi.ConvertSidToStringSidW(owner, ctypes.byref(owner_text))
        try:
            assert owner_text.value == sid
        finally:
            kernel.LocalFree(ctypes.cast(owner_text, ctypes.c_void_p))
        control, revision = wintypes.WORD(), wintypes.DWORD()
        assert advapi.GetSecurityDescriptorControl(
            actual, ctypes.byref(control), ctypes.byref(revision)
        )
        assert not control.value & 0x1000  # SE_DACL_PROTECTED must be absent.
    with pytest.raises(capture.CaptureError, match="^owner_acl_invalid$"):
        capture.assert_owner_only(path)
    assert path.read_bytes() == raw
    return path


def test_atomic_spool_runtime_absent_and_acl(tmp_path):
    spool = tmp_path / "spool"
    receipt = capture.write_envelope(spool, envelope())
    assert receipt.accepted_to_spool
    assert json.loads(receipt.path.read_bytes()) == envelope()
    assert list(spool.glob("*.json")) == [receipt.path]
    assert not list(spool.glob("*.part"))
    capture.assert_owner_only(spool)
    capture.assert_owner_only(receipt.path)


def test_same_retry_keeps_envelope_and_one_file(tmp_path):
    first = capture.write_envelope(tmp_path / "spool", envelope())
    second = capture.write_envelope(tmp_path / "spool", copy.deepcopy(envelope()))
    assert second.duplicate and second.path == first.path
    assert json.loads(second.path.read_bytes())["captured_at"] == "2026-10-04T00:00:00Z"


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("captured_at", "2026-10-04T00:00:01Z"),
        ("capture_policy_ref", "new-policy"),
        ("payload", {"snapshot": {"kind": "question", "title": "Changed"}}),
    ],
)
def test_conflicting_replay_cannot_overwrite(tmp_path, field, new_value):
    spool = tmp_path / "spool"
    first = capture.write_envelope(spool, envelope())
    modified = envelope()
    modified[field] = new_value
    with pytest.raises(capture.CaptureError, match="event_conflict"):
        capture.write_envelope(spool, modified)
    assert json.loads(first.path.read_bytes()) == envelope()
    assert len(list(spool.glob("*.json"))) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json secret-token",
        b'{"event_id":"secret-token","event_id":"other"}',
        b'{"secret-token":NaN}',
        b"x" * (capture.MAX_EVENT_BYTES + 1),
    ],
    ids=["malformed", "duplicate-key", "nonfinite", "oversize"],
)
def test_hook_malformed_oversize_non_deciding_and_redacted(tmp_path, raw):
    result = invoke(tmp_path / "spool", raw)
    assert result.returncode == 0 and result.stdout == b""
    assert b"secret-token" not in result.stderr
    assert b"decision-mesh capture unavailable:" in result.stderr
    assert not list((tmp_path / "spool").glob("*.json"))


def test_hook_success_emits_no_stdout_or_starts_runtime(tmp_path):
    result = invoke(tmp_path / "spool", json.dumps(envelope()).encode())
    assert result.returncode == 0 and result.stdout == result.stderr == b""
    assert len(list((tmp_path / "spool").glob("*.json"))) == 1
    assert not (tmp_path / "spool" / "runtime.json").exists()


def test_capacity_failure_diagnostic_has_no_payload(tmp_path):
    spool = tmp_path / "spool"
    data = envelope()
    data["payload"]["snapshot"]["title"] = "PRIVATE_SECRET"
    with pytest.raises(capture.CaptureError, match="spool_capacity"):
        capture.write_envelope(spool, data, max_spool_bytes=1)
    marker = spool / ".capture-failure"
    assert marker.exists()
    assert b"PRIVATE_SECRET" not in marker.read_bytes()
    assert json.loads(marker.read_bytes())["code"] == "spool_capacity"
    capture.assert_owner_only(marker)
    assert not list(spool.glob("*.json"))


def test_partial_restart_recovery_never_promotes_unaccepted_data(tmp_path):
    spool = capture.ensure_spool_dir(tmp_path / "spool")
    partial = secure_file(spool / ".capture-dead.part", "incomplete PRIVATE_SECRET")
    receipt = capture.write_envelope(spool, envelope())
    assert not partial.exists()
    assert json.loads(receipt.path.read_bytes()) == envelope()


def test_rename_failure_leaves_no_accepted_event(tmp_path, monkeypatch):
    def deny(*args):
        raise OSError("PRIVATE_SECRET")

    monkeypatch.setattr(capture.os, "rename", deny)
    with pytest.raises(capture.CaptureError, match="spool_io"):
        capture.write_envelope(tmp_path / "spool", envelope())
    assert not list((tmp_path / "spool").glob("*.json"))
    assert not list((tmp_path / "spool").glob("*.part"))


def test_flush_failure_leaves_no_accepted_event(tmp_path, monkeypatch):
    def deny(*args):
        raise OSError("PRIVATE_SECRET")

    monkeypatch.setattr(capture.os, "fsync", deny)
    with pytest.raises(capture.CaptureError, match="spool_io"):
        capture.write_envelope(tmp_path / "spool", envelope())
    assert not list((tmp_path / "spool").glob("*.json"))
    assert not list((tmp_path / "spool").glob("*.part"))


@pytest.mark.parametrize(
    "modify",
    [
        lambda e: e.update(schema_version=True),
        lambda e: e.update(unknown_top_level="PRIVATE_SECRET"),
        lambda e: e.update(captured_at="2026-10-04T00:00:00"),
        lambda e: e.update(revision=True),
        lambda e: e.update(event_kind=[]),
        lambda e: e.update(evidence_class=[]),
        lambda e: e.update(event_id="../escape"),
    ],
)
def test_primitive_validation(tmp_path, modify):
    data = envelope()
    modify(data)
    if data["event_id"] == "../escape":
        # IDs are data, not paths; containment still holds.
        receipt = capture.write_envelope(tmp_path / "spool", data)
        assert receipt.path.parent == (tmp_path / "spool").absolute()
    else:
        with pytest.raises(capture.CaptureError, match="invalid_envelope"):
            capture.write_envelope(tmp_path / "spool", data)


def test_policy_missing_invalid_inactive_unprotected_is_local_only(tmp_path):
    assert capture.read_capture_policy(tmp_path / "absent") is None
    folder = capture.ensure_spool_dir(tmp_path / "policy")
    path = secure_file(
        folder / "capture-policy.json",
        '{"schema_version":1,"capture_policy_ref":"policy-1","channel_active":true}',
    )
    assert capture.read_capture_policy(path) == "policy-1"
    for text in [
        "not JSON PRIVATE_SECRET",
        '{"schema_version":1,"capture_policy_ref":"policy-1","channel_active":false}',
        '{"schema_version":true,"capture_policy_ref":"policy-1","channel_active":true}',
        '{"schema_version":1,"capture_policy_ref":"policy-1","channel_active":true,"secret":"x"}',
    ]:
        path.write_text(text)
        assert capture.read_capture_policy(path) is None
    unprotected = tmp_path / "unprotected.json"
    unprotected.write_text('{"schema_version":1,"capture_policy_ref":"bad","channel_active":true}')
    if os.name != "nt":
        unprotected.chmod(0o644)
    assert capture.read_capture_policy(unprotected) is None


def test_metadata_allocate_once_policy_snapshot_not_reopened_on_retry(tmp_path):
    folder = capture.ensure_spool_dir(tmp_path / "policy")
    policy = secure_file(
        folder / "snapshot.json",
        '{"schema_version":1,"capture_policy_ref":"generation-1","channel_active":true}',
    )
    metadata = capture.new_capture_metadata(policy)
    data = envelope()
    data.update(metadata)
    receipt = capture.write_envelope(tmp_path / "spool", data)
    policy.write_text(
        '{"schema_version":1,"capture_policy_ref":"generation-2","channel_active":true}'
    )
    retry = capture.write_envelope(tmp_path / "spool", data)
    assert retry.duplicate and retry.path == receipt.path
    assert json.loads(retry.path.read_bytes())["capture_policy_ref"] == "generation-1"


def test_concurrent_capacity_is_serialized(tmp_path):
    spool = tmp_path / "spool"
    original = envelope()
    size = len(capture.envelope_bytes(original))
    capture.write_envelope(spool, original, max_spool_bytes=size * 4)

    def write(index):
        data = envelope()
        data["event_id"] = f"00000000-0000-4000-8000-{index:012d}"
        try:
            return capture.write_envelope(spool, data, max_spool_bytes=size * 4)
        except capture.CaptureError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(write, range(2, 8)))
    files = list(spool.glob("*.json"))
    assert len(files) == 4
    assert sum(p.stat().st_size for p in files) <= size * 4
    assert outcomes.count("spool_capacity") == 3


def test_capture_and_hook_import_do_not_import_pydantic():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import decision_mesh.capture; import decision_mesh.adapters.codex; assert 'pydantic' not in sys.modules",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("boundary,exit_code", [("before", 73), ("after", 74)])
def test_real_process_exit_around_atomic_rename_replays_without_losing_envelope(
    tmp_path, boundary, exit_code
):
    spool = tmp_path / "spool"
    program = """
import json, os, sys
from decision_mesh import capture
original = capture.os.rename
def crash(source, target):
    if sys.argv[2] == "before":
        os._exit(73)
    original(source, target)
    os._exit(74)
capture.os.rename = crash
capture.write_envelope(sys.argv[1], json.loads(sys.stdin.buffer.read()))
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(spool), boundary],
        input=json.dumps(envelope()).encode(),
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert process.returncode == exit_code
    if boundary == "before":
        assert not list(spool.glob("*.json"))
        assert len(list(spool.glob(".capture-*.part"))) == 1
    else:
        assert len(list(spool.glob("*.json"))) == 1
    receipt = capture.write_envelope(spool, envelope())
    assert receipt.duplicate == (boundary == "after")
    assert json.loads(receipt.path.read_bytes()) == envelope()
    assert not list(spool.glob(".capture-*.part"))
    assert len(list(spool.glob("*.json"))) == 1


def test_invalid_hook_arguments_do_not_leak_values(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "decision_mesh.capture",
            "--spool",
            str(tmp_path / "spool"),
            "--PRIVATE_SECRET",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0 and result.stdout == b""
    assert b"PRIVATE_SECRET" not in result.stderr
    assert result.stderr.strip() == b"decision-mesh capture unavailable: invalid_capture_arguments"


def test_public_atomic_metadata_publish_and_replace_are_owner_only(tmp_path):
    path = tmp_path / "secure" / "capture-policy.json"
    first = b'{"schema_version":1,"capture_policy_ref":"one","channel_active":true}'
    second = b'{"schema_version":1,"capture_policy_ref":"two","channel_active":true}'
    capture.atomic_write_owner_only(path, first)
    assert capture.read_capture_policy(path) == "one"
    capture.atomic_write_owner_only(path, second)
    assert capture.read_capture_policy(path) == "two"
    capture.assert_owner_only(path)
    assert not list(path.parent.glob("*.part"))


@pytest.mark.parametrize("mutation", ["edit", "remove", "appear"])
def test_expected_metadata_checks_after_fsync_and_preserves_intervening_change(
    tmp_path, monkeypatch, mutation
):
    path = tmp_path / "owned" / "metadata.bin"
    expected = None if mutation == "appear" else b"original"
    if expected is not None:
        capture.atomic_write_owner_only(path, expected)
    injected = []
    real_fsync = capture.os.fsync

    def fsync(fd):
        result = real_fsync(fd)
        if not injected:
            injected.append(True)
            if mutation == "remove":
                path.unlink()
            else:
                path.write_bytes(b"ordinary edit")
                if mutation == "appear":
                    capture._protect_new(path)
        return result

    monkeypatch.setattr(capture.os, "fsync", fsync)
    with pytest.raises(capture.CaptureError, match="local_file_changed"):
        capture.atomic_write_owner_only(path, b"proposed", expected_content=expected)
    assert injected == [True]
    assert (path.read_bytes() if path.exists() else None) == (None if mutation == "remove" else b"ordinary edit")
    assert not list(path.parent.glob("*.part"))


@pytest.mark.parametrize("expected", [None, b"", b"prior"])
def test_expected_metadata_matching_content_or_absence_publishes_owner_only(tmp_path, expected):
    path = tmp_path / "owned" / "metadata.bin"
    if expected is not None:
        capture.atomic_write_owner_only(path, expected)
    assert capture.atomic_write_owner_only(path, b"accepted", expected_content=expected) == path
    assert path.read_bytes() == b"accepted"
    capture.assert_owner_only(path)
    assert not list(path.parent.glob("*.part"))


def test_expected_absence_uses_exclusive_publication_even_after_last_check(tmp_path, monkeypatch):
    path = tmp_path / "owned" / "metadata.bin"
    real_link = capture.os.link
    def link(source, destination):
        path.write_bytes(b"newly appeared")
        capture._protect_new(path)
        return real_link(source, destination)
    monkeypatch.setattr(capture.os, "link", link)
    with pytest.raises(capture.CaptureError, match="local_file_io"):
        capture.atomic_write_owner_only(path, b"proposed", expected_content=None)
    assert path.read_bytes() == b"newly appeared"
    assert not list(path.parent.glob("*.part"))


@pytest.mark.parametrize("boundary", ["permissions", "reparse", "unreadable", "oversized"])
def test_expected_metadata_late_security_and_bounded_read_checks(tmp_path, monkeypatch, boundary):
    from pathlib import Path

    path = tmp_path / "owned" / "metadata.bin"
    capture.atomic_write_owner_only(path, b"original")
    injected = []
    security_before = []
    real_fsync, real_open, real_symlink = capture.os.fsync, Path.open, Path.is_symlink

    def fsync(fd):
        result = real_fsync(fd)
        if not injected:
            injected.append(True)
            if boundary == "permissions":
                path.unlink()
                insecure_file(path, b"original")
                security_before.append(file_security_state(path))
            elif boundary == "oversized":
                path.write_bytes(b"X" * 100_000)
        return result

    reads = []
    class BoundedRead:
        def __enter__(self):
            self.stream = real_open(path, "rb")
            return self
        def read(self, size):
            reads.append(size)
            assert size == 9  # Never allocate the independently enlarged target.
            return self.stream.read(size)
        def __exit__(self, *args):
            self.stream.close()

    def open_file(item, mode="r", *args, **kw):
        if item == path and mode == "rb" and injected:
            if boundary == "unreadable":
                raise PermissionError("synthetic denial")
            if boundary == "oversized":
                return BoundedRead()
        return real_open(item, mode, *args, **kw)

    monkeypatch.setattr(capture.os, "fsync", fsync)
    monkeypatch.setattr(Path, "open", open_file)
    monkeypatch.setattr(Path, "is_symlink", lambda item: (
        True if boundary == "reparse" and injected and item == path else real_symlink(item)
    ))
    code = {"permissions": "owner_acl_invalid", "reparse": "unsafe_path", "unreadable": "local_file_io", "oversized": "local_file_changed"}[boundary]
    with pytest.raises(capture.CaptureError, match=code):
        capture.atomic_write_owner_only(path, b"proposed", max_bytes=8, expected_content=b"original")
    assert injected == [True]
    with real_open(path, "rb") as current:
        assert current.read() == (b"X" * 100_000 if boundary == "oversized" else b"original")
    assert reads == ([9] if boundary == "oversized" else [])
    if boundary == "permissions":
        assert file_security_state(path) == security_before[0]
    assert not list(path.parent.glob("*.part"))


@pytest.mark.parametrize("expected", ["text", False, 3, b"too long for cap"])
def test_expected_metadata_rejects_invalid_expectation_without_writes(tmp_path, expected):
    path = tmp_path / "unused" / "metadata.bin"
    with pytest.raises(capture.CaptureError, match="invalid_expected_content"):
        capture.atomic_write_owner_only(path, b"new", max_bytes=8, expected_content=expected)
    assert not path.parent.exists()


def test_omitted_expected_content_retains_existing_unconditional_contract(tmp_path, monkeypatch):
    path = tmp_path / "owned" / "metadata.bin"
    capture.atomic_write_owner_only(path, b"original")
    real_fsync = capture.os.fsync
    injected = []
    def fsync(fd):
        result = real_fsync(fd)
        if not injected:
            injected.append(True)
            path.write_bytes(b"ordinary edit")
        return result
    monkeypatch.setattr(capture.os, "fsync", fsync)
    capture.atomic_write_owner_only(path, b"proposed")
    assert injected == [True] and path.read_bytes() == b"proposed"


def test_public_atomic_metadata_rejects_insecure_existing_file(tmp_path):
    folder = capture.ensure_spool_dir(tmp_path / "owned")
    path = insecure_file(folder / "unprotected.json", b"original")
    security_before = file_security_state(path)
    with pytest.raises(capture.CaptureError, match="^owner_acl_invalid$"):
        capture.atomic_write_owner_only(path, b"replacement")
    assert path.read_bytes() == b"original"
    assert file_security_state(path) == security_before
    assert not list(folder.glob("*.part"))


def test_public_owner_lock_is_exclusive_across_processes(tmp_path):
    directory = capture.ensure_spool_dir(tmp_path / "locks")
    path = directory / "request.lock"
    code = """
import sys
from pathlib import Path
from decision_mesh.capture import owner_file_lock, CaptureError
try:
    with owner_file_lock(Path(sys.argv[1]), timeout=0.05):
        print("incorrectly-acquired")
except CaptureError as error:
    print(error.code)
"""
    with capture.owner_file_lock(path):
        process = subprocess.run(
            [sys.executable, "-c", code, str(path)], check=False, capture_output=True, timeout=10
        )
        assert process.returncode == 0 and process.stdout.strip() == b"capture_busy"
    with capture.owner_file_lock(path, timeout=0):
        capture.assert_owner_only(path)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows security descriptor regression")
@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
@pytest.mark.parametrize("owner", ["current", "foreign", "missing"])
@pytest.mark.parametrize("identity", ["current-user", "local-administrator", "system"])
def test_native_descriptor_owner_is_independent_of_exact_protected_dacl(
    directory, owner, identity
):
    """Native in-memory descriptor fixture; no cross-account object assignment."""
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    sid = capture._windows_sid()
    if identity == "local-administrator":
        if not sid.startswith("S-1-5-21-"):
            pytest.skip("Local/domain account SID needed for the local administrator alias")
        sid = sid.rsplit("-", 1)[0] + "-500"
    elif identity == "system":
        sid = "S-1-5-18"
    owner_prefix = f"O:{sid}" if owner == "current" else ("O:BA" if owner == "foreign" else "")
    inherit = "OICI" if directory else ""
    text = f"{owner_prefix}D:P(A;{inherit};FA;;;{sid})"
    descriptor = ctypes.c_void_p()
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text, 1, ctypes.byref(descriptor), None
    )
    try:
        if owner == "current":
            capture._validate_windows_descriptor(descriptor, sid, directory=directory)
        else:
            code = "owner_sid_mismatch" if owner == "foreign" else "owner_acl_unavailable"
            with pytest.raises(capture.CaptureError, match=code):
                capture._validate_windows_descriptor(descriptor, sid, directory=directory)
    finally:
        kernel.LocalFree(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows owner-setting contract")
@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
def test_new_object_protection_explicitly_assigns_current_user_owner(
    tmp_path, monkeypatch, directory
):
    """Assert the native ownership request without changing token defaults."""
    import ctypes

    path = tmp_path / "new-object"
    if directory:
        path.mkdir()
    else:
        path.write_bytes(b"new")
    real_loader = ctypes.WinDLL
    advapi = real_loader("advapi32", use_last_error=True)
    requested = []

    def set_security(name, information, descriptor):
        assert information & 1, "New object protection must explicitly set its owner"
        capture._validate_windows_descriptor(
            descriptor, capture._windows_sid(), directory=directory
        )
        requested.append(information)
        return advapi.SetFileSecurityW(name, information, descriptor)

    class AdvapiProxy:
        SetFileSecurityW = staticmethod(set_security)

        def __getattr__(self, name):
            return getattr(advapi, name)

    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **kwargs: (
            AdvapiProxy() if name == "advapi32" else real_loader(name, **kwargs)
        )
    )
    capture._protect_new(path, directory=directory)
    assert len(requested) == 1
    capture.assert_owner_only(path)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows exact DACL regression")
@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
@pytest.mark.parametrize(
    "change",
    [
        "foreign-administrator", "administrators-group", "system", "extra-user",
        "extra-group", "unprotected", "wrong-inheritance", "inherit-only",
        "read-only", "deny", "empty", "null", "auto-inherited",
    ],
)
def test_native_descriptor_alias_does_not_relax_exact_dacl(directory, change):
    """In-memory local-administrator SID; never assign another account to a file."""
    import ctypes
    from ctypes import wintypes

    sid = capture._windows_sid()
    if not sid.startswith("S-1-5-21-"):
        pytest.skip("Local/domain account SID needed for the local administrator alias")
    sid = sid.rsplit("-", 1)[0] + "-500"
    inherit = "OICI" if directory else ""
    ace = f"(A;{inherit};FA;;;{sid})"
    foreign = "S-1-5-21-111-222-333-500"
    assert foreign != sid
    variants = {
        "foreign-administrator": f"D:P(A;{inherit};FA;;;{foreign})",
        "administrators-group": f"D:P(A;{inherit};FA;;;BA)",
        "system": f"D:P(A;{inherit};FA;;;SY)",
        "extra-user": f"D:P{ace}{ace}",
        "extra-group": f"D:P{ace}(A;;FA;;;BA)",
        "unprotected": f"D:{ace}",
        "wrong-inheritance": f"D:P(A;{'' if directory else 'OICI'};FA;;;{sid})",
        "inherit-only": f"D:P(A;{inherit}IO;FA;;;{sid})",
        "read-only": f"D:P(A;{inherit};FR;;;{sid})",
        "deny": f"D:P(D;{inherit};FA;;;{sid})",
        "empty": "D:P",
        "null": "D:NO_ACCESS_CONTROL",
        "auto-inherited": f"D:PAI{ace}",
    }
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{sid}{variants[change]}", 1, ctypes.byref(descriptor), None
    )
    try:
        with pytest.raises(capture.CaptureError, match="owner_acl_invalid"):
            capture._validate_windows_descriptor(descriptor, sid, directory=directory)
    finally:
        kernel.LocalFree(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows existing-directory refusal")
def test_existing_directory_with_other_owner_is_never_repaired(tmp_path, monkeypatch):
    path = capture.ensure_spool_dir(tmp_path / "existing")
    original_acl = capture._windows_acl
    modes = []

    def check_acl(path, create):
        modes.append(create)
        assert create is False
        return original_acl(path, create)

    monkeypatch.setattr(capture, "_windows_acl", check_acl)
    monkeypatch.setattr(capture, "_windows_sid", lambda: "S-1-5-18")
    with pytest.raises(capture.CaptureError, match="owner_sid_mismatch"):
        capture.ensure_spool_dir(path)
    assert modes == [False]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows object owner query")
def test_actual_file_owner_query_rejects_mocked_other_current_account(tmp_path, monkeypatch):
    path = tmp_path / "secure" / "metadata.bin"
    capture.atomic_write_owner_only(path, b"unchanged")
    monkeypatch.setattr(capture, "_windows_sid", lambda: "S-1-5-18")
    with pytest.raises(capture.CaptureError, match="owner_sid_mismatch"):
        capture.assert_owner_only(path)
    assert path.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name != "nt", reason="Native Windows disposable junction")
def test_policy_and_failure_diagnostics_reject_ancestor_junction(tmp_path):
    import _winapi

    real = capture.ensure_spool_dir(tmp_path / "real")
    spool = capture.ensure_spool_dir(real / "spool")
    policy = real / "policy.json"
    capture.atomic_write_owner_only(
        policy, b'{"schema_version":1,"capture_policy_ref":"test-policy","channel_active":true}'
    )
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(real), str(junction))
    try:
        assert junction.is_junction()
        assert capture.read_capture_policy(junction / "policy.json") is None
        with pytest.raises(capture.CaptureError, match="unsafe_path"):
            capture.assert_owner_only(junction / "policy.json")
        with pytest.raises(capture.CaptureError, match="unsafe_path"):
            capture.write_envelope(junction / "spool", envelope())
        result = invoke(junction / "spool", json.dumps(envelope()).encode())
        assert result.returncode == 0 and result.stdout == b""
        assert result.stderr.strip() == b"decision-mesh capture unavailable: unsafe_path"
        assert not (spool / ".capture-failure").exists()
        assert not (spool / ".diagnostic.lock").exists()
        assert not list(spool.iterdir())
    finally:
        # Remove only this disposable link, never recursively follow the target.
        junction.rmdir()


@pytest.mark.parametrize("kind", ["metadata", "diagnostic"])
def test_repeated_real_crashes_before_replace_bound_and_recover_partials(tmp_path, kind):
    folder = capture.ensure_spool_dir(tmp_path / kind)
    target = folder / "metadata.bin"
    capture.atomic_write_owner_only(target, b"original accepted data")
    program = """
import json, os, sys
from pathlib import Path
from decision_mesh import capture
capture.os.replace = lambda *args: os._exit(77)
if sys.argv[2] == "metadata":
    capture.atomic_write_owner_only(Path(sys.argv[1]) / "metadata.bin", b"superseded synthetic data")
else:
    capture.write_envelope(sys.argv[1], json.loads(sys.stdin.buffer.read()), max_spool_bytes=1)
"""
    for _ in range(3):
        process = subprocess.run(
            [sys.executable, "-c", program, str(folder), kind],
            input=json.dumps(envelope()).encode(),
            check=False,
            capture_output=True,
            timeout=10,
        )
        assert process.returncode == 77
        assert len(list(folder.glob(f".{kind}*.part"))) == 1
        assert target.read_bytes() == b"original accepted data"
    if kind == "metadata":
        # An unrelated target safely reclaims only abandoned scoped publications.
        other = capture.atomic_write_owner_only(folder / "other.bin", b"other accepted data")
        assert other.read_bytes() == b"other accepted data"
        assert target.read_bytes() == b"original accepted data"
    else:
        receipt = capture.write_envelope(folder, envelope())
        assert json.loads(receipt.path.read_bytes()) == envelope()
    assert not list(folder.glob(f".{kind}*.part"))


@pytest.mark.parametrize("kind", ["metadata", "diagnostic"])
def test_recovery_never_deletes_another_live_publishers_partial(tmp_path, kind):
    import time

    folder = capture.ensure_spool_dir(tmp_path / kind)
    signal_path = tmp_path / "ready"
    program = """
import json, sys
from pathlib import Path
from decision_mesh import capture
original = capture.os.replace
def pause(source, target):
    Path(sys.argv[3]).write_text("ready")
    sys.stdin.buffer.read(1)
    original(source, target)
capture.os.replace = pause
if sys.argv[2] == "metadata":
    capture.atomic_write_owner_only(Path(sys.argv[1]) / "active.bin", b"active accepted data")
else:
    try:
        capture.write_envelope(sys.argv[1], json.loads(sys.argv[4]), max_spool_bytes=1)
    except capture.CaptureError:
        pass
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            program,
            str(folder),
            kind,
            str(signal_path),
            json.dumps(envelope()),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not signal_path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert signal_path.exists(), "owned test publisher never reached replace boundary"
        partials = list(folder.glob(f".{kind}*.part"))
        assert len(partials) == 1
        original_bytes = partials[0].read_bytes()
        # This publisher and capture recovery run while the first target is live.
        other = capture.atomic_write_owner_only(folder / "other.bin", b"other accepted data")
        receipt = capture.write_envelope(folder, envelope())
        assert partials[0].read_bytes() == original_bytes
        assert other.read_bytes() == b"other accepted data"
        assert json.loads(receipt.path.read_bytes()) == envelope()
        stdout, stderr = process.communicate(input=b"x", timeout=5)
        assert process.returncode == 0, stderr.decode()
        assert stdout == b""
        assert not list(folder.glob(f".{kind}*.part"))
        if kind == "metadata":
            assert (folder / "active.bin").read_bytes() == b"active accepted data"
        else:
            assert (folder / ".capture-failure").exists()
    finally:
        if process.poll() is None:
            # This is only the subprocess created by this test, never a host session.
            process.kill()
            process.communicate(timeout=5)


def test_legacy_unscoped_partial_is_preserved_and_counts_toward_temporary_capacity(
    tmp_path, monkeypatch
):
    folder = capture.ensure_spool_dir(tmp_path / "metadata")
    legacy = secure_file(folder / ".metadata-00000000000000000000000000000000.part", "12345678")
    monkeypatch.setattr(capture, "MAX_PARTIAL_BYTES", 8)
    with pytest.raises(capture.CaptureError, match="local_partial_capacity"):
        capture.atomic_write_owner_only(folder / "target.bin", b"x", max_bytes=8)
    assert legacy.read_bytes() == b"12345678"
    assert not (folder / "target.bin").exists()
    assert list(folder.glob("*.part")) == [legacy]


def test_legacy_partial_counts_toward_ready_spool_capacity_without_unsafe_sweep(tmp_path):
    spool = capture.ensure_spool_dir(tmp_path / "spool")
    legacy = secure_file(spool / ".diagnostic-00000000000000000000000000000000.part", "12345678")
    with pytest.raises(capture.CaptureError, match="spool_capacity"):
        capture.write_envelope(
            spool, envelope(), max_spool_bytes=len(capture.envelope_bytes(envelope())) + 7
        )
    assert legacy.read_bytes() == b"12345678"
    assert not list(spool.glob("*.json"))


def test_concurrent_metadata_targets_leave_only_accepted_files(tmp_path):
    import time

    folder = capture.ensure_spool_dir(tmp_path / "metadata")
    seed = capture.atomic_write_owner_only(folder / "seed.bin", b"seed")

    def publish(index):
        path = folder / f"target-{index}.bin"
        partial = folder / f".metadata-{capture._metadata_identity(path)}.part"
        # Lock waits are deliberately bounded. Retry only an unaccepted busy
        # attempt, never other errors, and fail if the fixed retry cap is spent.
        for attempt in range(8):
            try:
                capture.atomic_write_owner_only(path, f"accepted-{index}".encode())
                return path
            except capture.CaptureError as error:
                if error.code != "capture_busy":
                    raise
                assert not path.exists()
                assert not partial.exists()
                assert seed.read_bytes() == b"seed"
                if attempt == 7:
                    raise
                time.sleep(0.01)

    with ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(publish, range(16)))
    assert len(set(paths)) == 16
    assert all(
        path.read_bytes() == f"accepted-{index}".encode() for index, path in enumerate(paths)
    )
    assert seed.read_bytes() == b"seed"
    assert not list(folder.glob("*.part"))


@pytest.mark.parametrize("existing", [False, True], ids=["new-target", "replacement"])
def test_metadata_quota_busy_preserves_accepted_bytes_then_retry_succeeds(tmp_path, existing):
    folder = capture.ensure_spool_dir(tmp_path / "metadata")
    seed = capture.atomic_write_owner_only(folder / "seed.bin", b"accepted seed")
    target = folder / "target.bin"
    if existing:
        capture.atomic_write_owner_only(target, b"accepted target")
    partial = folder / f".metadata-{capture._metadata_identity(target)}.part"

    # Hold the real quota lock while another thread exhausts the unchanged
    # production timeout. No mocked error or production timeout adjustment.
    with capture.owner_file_lock(folder / ".partial-quota.lock"):
        with ThreadPoolExecutor(max_workers=1) as pool:
            attempt = pool.submit(capture.atomic_write_owner_only, target, b"replacement")
            with pytest.raises(capture.CaptureError, match="^capture_busy$"):
                attempt.result(timeout=5)
        assert seed.read_bytes() == b"accepted seed"
        if existing:
            assert target.read_bytes() == b"accepted target"
        else:
            assert not target.exists()
        assert not partial.exists()

    # Exactly one retry after release: busy preserved the accepted content;
    # replacement occurs only on this successfully returned write.
    assert capture.atomic_write_owner_only(target, b"replacement") == target
    assert target.read_bytes() == b"replacement"
    assert seed.read_bytes() == b"accepted seed"
    assert not list(folder.glob("*.part"))


@pytest.mark.skipif(os.name != "nt", reason="Native Windows file creation crash boundary")
@pytest.mark.parametrize(
    "kind,boundary",
    [
        ("metadata", "partial"),
        ("diagnostic", "partial"),
        ("capture", "partial"),
        ("metadata", "target-lock"),
        ("metadata", "quota-lock"),
        ("diagnostic", "diagnostic-lock"),
        ("capture", "capture-lock"),
    ],
)
def test_real_exit_immediately_after_file_creation_is_recoverable(tmp_path, kind, boundary):
    folder = capture.ensure_spool_dir(tmp_path / kind)
    target = capture.atomic_write_owner_only(folder / "metadata.bin", b"original accepted data")
    if boundary == "partial":
        prior_event = capture.write_envelope(folder, envelope()).path
        prior_event_bytes = prior_event.read_bytes()
    else:
        # Only this test owns the directory and no publisher is running. Remove
        # its idle setup locks so the child exercises creation of each lock.
        for lock in folder.glob("*.lock"):
            lock.unlink()
        prior_event = None
    pattern = {
        "partial": f".{kind}-*.part" if kind != "diagnostic" else ".diagnostic.part",
        "target-lock": ".metadata-*.lock",
        "quota-lock": ".partial-quota.lock",
        "diagnostic-lock": ".diagnostic.lock",
        "capture-lock": ".capture.lock",
    }[boundary]
    program = """
import json, msvcrt, os, sys
from pathlib import Path
from decision_mesh import capture
folder = Path(sys.argv[1])
original_open = os.open
original_adopt = msvcrt.open_osfhandle
def crash_if_created():
    if list(folder.glob(sys.argv[3])):
        os._exit(78)
def open_then_crash(*args, **kwargs):
    fd = original_open(*args, **kwargs)
    crash_if_created()
    return fd
def adopt_then_crash(*args, **kwargs):
    # CreateFileW has returned; no CRT descriptor or later ACL call exists yet.
    crash_if_created()
    return original_adopt(*args, **kwargs)
os.open = open_then_crash
msvcrt.open_osfhandle = adopt_then_crash
if sys.argv[2] == "metadata":
    capture.atomic_write_owner_only(folder / "metadata.bin", b"replacement")
else:
    event = json.loads(sys.stdin.buffer.read())
    capacity = 1 if sys.argv[2] == "diagnostic" else capture.MAX_SPOOL_BYTES
    capture.write_envelope(folder, event, max_spool_bytes=capacity)
"""
    data = envelope()
    data["event_id"] = "00000000-0000-4000-8000-000000000002"
    result = subprocess.run(
        [sys.executable, "-c", program, str(folder), kind, pattern],
        input=json.dumps(data).encode(),
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 78, result.stderr.decode()
    assert result.stdout == result.stderr == b""
    leftovers = list(folder.glob(pattern))
    assert len(leftovers) == 1
    # This must already be the final strict ACL, despite no post-create action.
    capture.assert_owner_only(leftovers[0])
    assert leftovers[0].stat().st_size == 0
    if boundary != "partial":
        with capture.owner_file_lock(leftovers[0], timeout=0):
            capture.assert_owner_only(leftovers[0])
    other = capture.atomic_write_owner_only(folder / "other.bin", b"other accepted data")
    receipt = capture.write_envelope(folder, data)
    assert other.read_bytes() == b"other accepted data"
    assert json.loads(receipt.path.read_bytes()) == data
    assert target.read_bytes() == b"original accepted data"
    if prior_event is not None:
        assert prior_event.read_bytes() == prior_event_bytes
    assert not list(folder.glob("*.part"))


@pytest.mark.skipif(os.name != "nt", reason="Native Windows inherited ACL rejection")
@pytest.mark.parametrize("kind", ["lock", "metadata", "diagnostic"])
def test_existing_insecure_reserved_files_are_never_repaired(tmp_path, kind):
    folder = capture.ensure_spool_dir(tmp_path / kind)
    if kind == "lock":
        path = folder / ".capture.lock"
    elif kind == "metadata":
        identity = capture._metadata_identity(folder / "target.bin")
        with capture.owner_file_lock(folder / f".metadata-{identity}.lock"):
            pass
        path = folder / f".metadata-{identity}.part"
    else:
        path = folder / ".diagnostic.part"
    # Explicit current owner isolates the invalid DACL from creator defaults.
    insecure_file(path, b"existing unaccepted data")
    security_before = file_security_state(path)
    with pytest.raises(capture.CaptureError, match="^owner_acl_invalid$"):
        capture.write_envelope(folder, envelope())
    assert path.read_bytes() == b"existing unaccepted data"
    assert file_security_state(path) == security_before
    with pytest.raises(capture.CaptureError, match="^owner_acl_invalid$"):
        capture.assert_owner_only(path)
    assert not list(folder.glob("*.json"))
