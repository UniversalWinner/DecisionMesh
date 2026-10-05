"""Bounded, non-deciding, standard-library-only capture boundary.

Durable spool acceptance is not runtime ingestion or source acknowledgement.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import stat
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_EVENT_BYTES = 256 * 1024
MAX_SPOOL_BYTES = 128 * 1024 * 1024
MAX_POLICY_BYTES = 4096
MAX_PARTIAL_BYTES = 128 * 1024 * 1024
_UNCONDITIONAL_CONTENT = object()
EVENT_KINDS = frozenset(
    {
        "observation.recorded",
        "request.opened",
        "request.updated",
        "request.resolved",
        "request.withdrawn",
        "request.corrected",
        "execution.updated",
        "source.health",
    }
)
EVIDENCE_CLASSES = frozenset(
    {"gate_observed", "prompt_confirmed", "source_authoritative", "producer_reported"}
)
FIELDS = frozenset(
    {
        "schema_version",
        "producer_id",
        "event_id",
        "event_kind",
        "source_request_id",
        "revision",
        "occurred_at",
        "captured_at",
        "source_context",
        "evidence_class",
        "capture_policy_ref",
        "payload",
    }
)


class CaptureError(Exception):
    """Only a fixed redacted code is safe to report at the hook boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CaptureReceipt:
    event_id: str
    path: Path
    duplicate: bool = False
    accepted_to_spool: bool = True


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise CaptureError("invalid_envelope")
    try:
        value_dt = datetime.fromisoformat(value)
    except ValueError:
        raise CaptureError("invalid_envelope") from None
    if value_dt.tzinfo is None or value_dt.utcoffset().total_seconds() != 0:
        raise CaptureError("invalid_envelope")
    return value_dt


def _identifier(value: Any, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
        raise CaptureError("invalid_envelope")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError("invalid_json")
        result[key] = value
    return result


def parse_json(raw: bytes | str, max_bytes: int = MAX_EVENT_BYTES) -> dict[str, Any]:
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if len(raw) > max_bytes:
            raise CaptureError("event_too_large")
        value = json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(CaptureError("invalid_json")),
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CaptureError("invalid_json") from None
    if not isinstance(value, dict):
        raise CaptureError("invalid_json")
    return value


def envelope_bytes(envelope: dict[str, Any]) -> bytes:
    """Primitive boundary checks only; runtime performs full Pydantic validation."""
    if not isinstance(envelope, dict) or set(envelope) != FIELDS:
        raise CaptureError("invalid_envelope")
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise CaptureError("invalid_envelope")
    for key in ("producer_id", "event_id"):
        _identifier(envelope[key])
    for key in ("source_request_id", "capture_policy_ref"):
        _identifier(envelope[key], nullable=True)
    _utc(envelope["captured_at"])
    if envelope["occurred_at"] is not None:
        _utc(envelope["occurred_at"])
    if (
        not isinstance(envelope["event_kind"], str)
        or not isinstance(envelope["evidence_class"], str)
        or envelope["event_kind"] not in EVENT_KINDS
        or envelope["evidence_class"] not in EVIDENCE_CLASSES
    ):
        raise CaptureError("invalid_envelope")
    revision = envelope["revision"]
    if revision is not None and (type(revision) is not int or revision < 1):
        raise CaptureError("invalid_envelope")
    if envelope["event_kind"].startswith(("request.", "execution.")) and (
        envelope["source_request_id"] is None or revision is None
    ):
        raise CaptureError("invalid_envelope")
    if not isinstance(envelope["payload"], dict) or not isinstance(
        envelope["source_context"], dict
    ):
        raise CaptureError("invalid_envelope")
    try:
        result = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise CaptureError("invalid_envelope") from None
    if len(result) > MAX_EVENT_BYTES:
        raise CaptureError("event_too_large")
    return result


def _windows_sid() -> str:
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise CaptureError("owner_acl_unavailable")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buf, needed.value, ctypes.byref(needed)):
            raise CaptureError("owner_acl_unavailable")
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_text)):
            raise CaptureError("owner_acl_unavailable")
        try:
            return sid_text.value
        finally:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


def _windows_acl(path: Path, create: bool) -> None:
    """Protected DACL with exactly the current user SID, without inherited grants."""
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    sid = _windows_sid()
    if create:
        descriptor = ctypes.c_void_p()
        inheritance = "OICI" if path.is_dir() else ""
        sddl = f"O:{sid}D:P(A;{inheritance};FA;;;{sid})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise CaptureError("owner_acl_unavailable")
        try:
            # PROTECTED_DACL | OWNER | DACL: a default owner may differ from TokenUser.
            if not advapi.SetFileSecurityW(str(path), 0x80000005, descriptor):
                raise CaptureError("owner_acl_unavailable")
        finally:
            kernel.LocalFree(descriptor)
    needed = wintypes.DWORD()
    # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
    advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
    buf = ctypes.create_string_buffer(needed.value)
    if not advapi.GetFileSecurityW(str(path), 5, buf, needed.value, ctypes.byref(needed)):
        raise CaptureError("owner_acl_unavailable")
    _validate_windows_descriptor(buf, sid, directory=path.is_dir())


def _validate_windows_descriptor(descriptor: Any, current_sid: str, *, directory: bool) -> None:
    """Validate native descriptor ownership and DACL without changing an object."""
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    owner = ctypes.c_void_p()
    defaulted = wintypes.BOOL()
    if (
        not advapi.GetSecurityDescriptorOwner(
            descriptor, ctypes.byref(owner), ctypes.byref(defaulted)
        )
        or not owner.value
    ):
        raise CaptureError("owner_acl_unavailable")
    text = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(owner, ctypes.byref(text)):
        raise CaptureError("owner_acl_unavailable")
    try:
        if text.value != current_sid:
            raise CaptureError("owner_sid_mismatch")
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    text = wintypes.LPWSTR()
    if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, 1, 4, ctypes.byref(text), None
    ):
        raise CaptureError("owner_acl_unavailable")
    try:
        inheritance = "OICI" if directory else ""
        # Windows may render a full SID as its SDDL alias (e.g. LA or SY).
        # Serialize the exact expected descriptor through the same native API;
        # retain exact owner, principal, ACE count, access and inheritance checks.
        expected = ctypes.c_void_p()
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"D:P(A;{inheritance};FA;;;{current_sid})", 1, ctypes.byref(expected), None
        ):
            raise CaptureError("owner_acl_unavailable")
        try:
            expected_text = wintypes.LPWSTR()
            if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                expected, 1, 4, ctypes.byref(expected_text), None
            ):
                raise CaptureError("owner_acl_unavailable")
            try:
                if text.value != expected_text.value:
                    raise CaptureError("owner_acl_invalid")
            finally:
                kernel.LocalFree(ctypes.cast(expected_text, ctypes.c_void_p))
        finally:
            kernel.LocalFree(expected)
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _validate_path(path: Path | str) -> Path:
    """Non-mutating rejection of symlink/junction traversal at every component."""
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
            raise CaptureError("unsafe_path")
    return path


def assert_owner_only(path: Path) -> None:
    path = _validate_path(path)
    if os.name == "nt":
        _windows_acl(path, False)
    else:
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CaptureError("owner_acl_invalid")


def _protect_new(path: Path, directory: bool = False) -> None:
    """Protect only an object the caller has just created successfully."""
    if os.name == "nt":
        _windows_acl(path, True)
    else:
        path.chmod(0o700 if directory else 0o600)
    assert_owner_only(path)


def ensure_spool_dir(path: Path | str) -> Path:
    path = _validate_path(path)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        assert_owner_only(path)
    else:
        _protect_new(path, directory=True)
    if not path.is_dir():
        raise CaptureError("unsafe_path")
    return path


def _create_owner_only(path: Path, flags: int) -> int:
    """Exclusively create a file with its final permissions in the creation call.

    A process exit before the next Python instruction must leave a file that
    passes the same strict owner check as a fully initialized helper file.
    """
    path = _validate_path(path)
    if os.name != "nt":
        return os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)

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
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    sid = _windows_sid()
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{sid}D:P(A;;FA;;;{sid})", 1, ctypes.byref(descriptor), None
    ):
        raise CaptureError("owner_acl_unavailable")
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        # GENERIC_READ | GENERIC_WRITE; share read/write; CREATE_NEW; NORMAL.
        # CREATE_NEW must never apply this descriptor to an existing object.
        handle = kernel.CreateFileW(str(path), 0xC0000000, 3, ctypes.byref(attributes), 1, 128, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)
    try:
        # On success the CRT descriptor owns the native, non-inheritable handle.
        return msvcrt.open_osfhandle(handle, flags | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        kernel.CloseHandle(handle)
        raise


@contextmanager
def owner_file_lock(lock_path: Path | str, timeout: float = 0.25) -> Iterator[None]:
    """Exclusive OS lock; lock acquisition is bounded and does not start a runtime."""
    if (
        not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 <= timeout <= 60
    ):
        raise CaptureError("invalid_lock_timeout")
    lock_path = Path(lock_path).absolute()
    ensure_spool_dir(lock_path.parent)
    try:
        fd = _create_owner_only(lock_path, os.O_RDWR)
    except FileExistsError:
        assert_owner_only(lock_path)
        fd = os.open(lock_path, os.O_RDWR)
    else:
        try:
            assert_owner_only(lock_path)
        except BaseException:
            os.close(fd)
            raise
    stream = os.fdopen(fd, "r+b", buffering=0)
    locked = False
    try:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b"0")
        deadline = time.monotonic() + timeout
        while True:
            try:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise CaptureError("capture_busy") from None
                time.sleep(0.01)
        yield
    finally:
        if locked:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream, fcntl.LOCK_UN)
        stream.close()


def _metadata_identity(path: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(path.absolute())).encode("utf-8")).hexdigest()


def _remove_owned_partial(path: Path) -> None:
    if path.exists() or path.is_symlink():
        assert_owner_only(path)
        path.unlink()


def _recover_metadata_partials(directory: Path) -> None:
    """Only scoped partials with their own existing lock are reclaimable."""
    for partial in directory.glob(".metadata-*.part"):
        identity = partial.name[len(".metadata-") : -len(".part")]
        if len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            # Legacy UUID partials have no recoverable publisher ownership.
            continue
        lock_path = directory / f".metadata-{identity}.lock"
        if not lock_path.exists():
            continue
        try:
            with owner_file_lock(lock_path, timeout=0):
                _remove_owned_partial(partial)
        except CaptureError as error:
            if error.code != "capture_busy":
                raise


def _partial_usage(directory: Path) -> int:
    total = 0
    for partial in directory.glob("*.part"):
        try:
            assert_owner_only(partial)
            total += partial.stat().st_size
        except FileNotFoundError:
            continue
        except CaptureError as error:
            # Native security query can race a different target completing replace.
            if error.code == "owner_acl_unavailable" and not partial.exists():
                continue
            raise
    return total


def atomic_write_owner_only(
    path: Path | str,
    raw: bytes,
    *,
    max_bytes: int = MAX_EVENT_BYTES,
    expected_content: object = _UNCONDITIONAL_CONTENT,
) -> Path:
    """Publish bounded metadata under a per-target OS lock.

    Callers still own semantic serialization/revisions. Existing insecure objects
    are rejected; no ownership or permission repair is performed.
    Omitted expected_content preserves unconditional publication. Bytes require
    exact prior content after preparation; None requires exclusive creation.
    Replacement is not atomic compare-and-swap against independent editors.
    """
    path = _validate_path(path)
    if (
        not isinstance(raw, bytes)
        or type(max_bytes) is not int
        or not 0 <= max_bytes <= MAX_PARTIAL_BYTES
        or len(raw) > max_bytes
    ):
        raise CaptureError("local_file_too_large")
    if expected_content is not _UNCONDITIONAL_CONTENT and expected_content is not None and (
        not isinstance(expected_content, bytes) or len(expected_content) > max_bytes
    ):
        raise CaptureError("invalid_expected_content")
    directory = ensure_spool_dir(path.parent)
    if path.exists():
        assert_owner_only(path)
    _recover_metadata_partials(directory)
    identity = _metadata_identity(path)
    temporary = directory / f".metadata-{identity}.part"
    lock_path = directory / f".metadata-{identity}.lock"
    with owner_file_lock(lock_path):
        # This target's lock proves no active publisher owns its fixed partial.
        _remove_owned_partial(temporary)
        if path.exists():
            assert_owner_only(path)
        fd = -1
        stream = None
        try:
            with owner_file_lock(directory / ".partial-quota.lock"):
                if _partial_usage(directory) + len(raw) > MAX_PARTIAL_BYTES:
                    raise CaptureError("local_partial_capacity")
                fd = _create_owner_only(temporary, os.O_WRONLY)
                assert_owner_only(temporary)
                stream = os.fdopen(fd, "wb")
                fd = -1
                try:
                    # Allocate the full bytes before releasing the quota lock.
                    stream.write(raw)
                    stream.flush()
                except BaseException:
                    stream.close()
                    raise
            with stream:
                os.fsync(stream.fileno())
            if expected_content is not _UNCONDITIONAL_CONTENT:
                # Locks, recovery, writes and fsync all precede this check. Do
                # not mistake an earlier observation for mutation authority.
                _validate_path(path)
                assert_owner_only(directory)
                actual = None
                if path.exists():
                    assert_owner_only(path)
                    with path.open("rb") as current:
                        actual = current.read(max_bytes + 1)
                if actual != expected_content:
                    raise CaptureError("local_file_changed")
            if expected_content is None:
                os.link(temporary, path)  # A newly appeared destination cannot be overwritten.
            else:
                os.replace(temporary, path)
            _flush_directory(directory)
            return path
        except OSError:
            raise CaptureError("local_file_io") from None
        finally:
            if fd != -1:
                os.close(fd)
            if stream is not None and not stream.closed:
                stream.close()
            _remove_owned_partial(temporary)


@contextmanager
def _spool_lock(directory: Path, timeout: float = 0.25) -> Iterator[None]:
    with owner_file_lock(directory / ".capture.lock", timeout=timeout):
        yield


def read_capture_policy(path: Path | str | None) -> str | None:
    """Unreadable/unprotected/malformed/inactive policy means local-only capture."""
    if path is None:
        return None
    path = Path(path)
    try:
        assert_owner_only(path)
        with path.open("rb") as stream:
            snapshot = parse_json(stream.read(MAX_POLICY_BYTES + 1), MAX_POLICY_BYTES)
        if set(snapshot) != {"schema_version", "capture_policy_ref", "channel_active"}:
            return None
        if (
            type(snapshot["schema_version"]) is not int
            or snapshot["schema_version"] != 1
            or snapshot["channel_active"] is not True
        ):
            return None
        _identifier(snapshot["capture_policy_ref"])
        return snapshot["capture_policy_ref"]
    except (OSError, CaptureError):
        return None


def new_capture_metadata(policy_path: Path | str | None = None) -> dict[str, Any]:
    """Allocate once. Retry callers must retain and reuse this whole receipt."""
    return {
        "event_id": str(uuid.uuid4()),
        "captured_at": utc_now(),
        "capture_policy_ref": read_capture_policy(policy_path),
    }


def _flush_directory(directory: Path) -> None:
    if os.name != "nt":
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _recover_diagnostic_partial(directory: Path) -> None:
    assert_owner_only(directory)
    try:
        with owner_file_lock(directory / ".diagnostic.lock", timeout=0):
            _remove_owned_partial(directory / ".diagnostic.part")
    except CaptureError as error:
        if error.code != "capture_busy":
            raise


def _record_failure(directory: Path, code: str) -> None:
    """One bounded diagnostic partial; rejected paths receive no filesystem write."""
    try:
        assert_owner_only(directory)
        with owner_file_lock(directory / ".diagnostic.lock", timeout=0.05):
            temporary = directory / ".diagnostic.part"
            _remove_owned_partial(temporary)
            path = directory / ".capture-failure"
            prior: dict[str, Any] = {}
            if path.exists():
                assert_owner_only(path)
                with path.open("rb") as stream:
                    prior = parse_json(stream.read(1025), 1024)
            marker = {
                "code": code,
                "first_failure_at": prior.get("first_failure_at", utc_now()),
                "last_failure_at": utc_now(),
                "lost_count_lower_bound": 1,
            }
            fd = -1
            try:
                fd = _create_owner_only(temporary, os.O_WRONLY)
                assert_owner_only(temporary)
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    raw = json.dumps(marker, separators=(",", ":")).encode()
                    if len(raw) > 1024:
                        raise CaptureError("invalid_diagnostic")
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if fd != -1:
                    os.close(fd)
                _remove_owned_partial(temporary)
    except (OSError, CaptureError, ValueError, TypeError):
        pass


def write_envelope(
    spool_dir: Path | str, envelope: dict[str, Any], *, max_spool_bytes: int = MAX_SPOOL_BYTES
) -> CaptureReceipt:
    """Atomically publish; a replay preserves the entire original envelope."""
    directory = Path(spool_dir)
    temporary: Path | None = None
    try:
        raw = envelope_bytes(envelope)
        directory = ensure_spool_dir(directory)
        _recover_diagnostic_partial(directory)
        _recover_metadata_partials(directory)
        stamp = _utc(envelope["captured_at"]).strftime("%Y%m%dT%H%M%S%fZ")
        identity = json.dumps(
            [envelope["producer_id"], envelope["event_id"]], separators=(",", ":")
        ).encode()
        suffix = hashlib.sha256(identity).hexdigest()
        target = directory / f"{stamp}-{suffix}.json"
        with _spool_lock(directory):
            # Holding the single writer lock proves these unaccepted partial files
            # have no active writer. They cannot be promoted to accepted events.
            for partial in directory.glob(".capture-*.part"):
                assert_owner_only(partial)
                partial.unlink()
            # Identity is independent of timestamp, so changed retry timestamps
            # conflict instead of creating a second event.
            matches = list(directory.glob(f"*-{suffix}.json"))
            if matches:
                if len(matches) != 1:
                    raise CaptureError("event_conflict")
                assert_owner_only(matches[0])
                with matches[0].open("rb") as stream:
                    existing = stream.read(MAX_EVENT_BYTES + 1)
                if existing != raw:
                    raise CaptureError("event_conflict")
                return CaptureReceipt(envelope["event_id"], matches[0], duplicate=True)
            total = sum(
                entry.stat().st_size for entry in directory.glob("*.json") if entry.is_file()
            )
            if total + _partial_usage(directory) + len(raw) > max_spool_bytes:
                raise CaptureError("spool_capacity")
            temporary = directory / f".capture-{uuid.uuid4().hex}.part"
            fd = _create_owner_only(temporary, os.O_WRONLY)
            try:
                assert_owner_only(temporary)
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Never replace an existing accepted event.
                os.rename(temporary, target)
                temporary = None
                _flush_directory(directory)
            finally:
                if fd != -1:
                    os.close(fd)
        return CaptureReceipt(envelope["event_id"], target)
    except CaptureError as error:
        _record_failure(directory, error.code)
        raise
    except OSError:
        _record_failure(directory, "spool_io")
        raise CaptureError("spool_io") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


class ObserverArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CaptureError("invalid_capture_arguments")


def main(argv: list[str] | None = None) -> int:
    """Observer CLI. Always return success and never emit permission decisions."""
    parser = ObserverArgumentParser(add_help=False)
    parser.add_argument("--spool", required=True)
    args = None
    try:
        args = parser.parse_args(argv)
        raw = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
        write_envelope(args.spool, parse_json(raw))
    except (CaptureError, OSError, SystemExit) as error:
        code = error.code if isinstance(error, CaptureError) else "capture_unavailable"
        if args is not None:
            _record_failure(Path(args.spool), code)
        print(f"decision-mesh capture unavailable: {code}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
