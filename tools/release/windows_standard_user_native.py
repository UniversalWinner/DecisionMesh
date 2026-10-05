"""Small WinAPI boundary for the proposed disposable-host qualification.

No API executes on import. Real use is guarded by check_windows_standard_user.
"""
from __future__ import annotations

import ctypes as C
import os
import socket
import stat
import struct
import subprocess
import time
from ctypes import wintypes as W
from pathlib import Path


class NativeError(RuntimeError):
    """Fixed codes and captured numeric status; never format native arguments."""

    def __init__(self, code: str, *, operation: str | None = None,
                 hresult: int | None = None, winerror: int | None = None,
                 errno: int | None = None, residual: dict | None = None) -> None:
        super().__init__(code)
        self.code, self.operation = code, operation
        self.hresult, self.winerror, self.errno = hresult, winerror, errno
        self.residual = residual


DIAGNOSTIC_CODES = frozenset({
    "new_profile_required", "profile_registration_invalid", "profile_hive_query_failed",
    "profile_cleanup_unproven", "profile_delete_failed", "profile_delete_not_observed",
    "profile_registration_remains", "profile_binding_mismatch", "profile_identity_changed",
    "local_path_required", "noncanonical_path", "missing_ancestor", "reparse_path",
    "account_cleanup_identity_changed", "account_cleanup_not_observed",
    "failed_creation_account_state_uncertain", "account_query_failed", "account_delete_failed",
    "fixture_cleanup_incomplete", "fixture_changed_during_cleanup", "fixture_identity_changed",
    "owned_processes_not_exited", "suspended_child_not_exited", "native_api_failed",
    "profile_observation_failed", "owned_work_path_invalid",
})

RESIDUAL_LABELS = ("profile_root", "profile_registry", "owned_work", "user_data", "environment")
DIAGNOSTIC_OPERATIONS = frozenset({
    "CreateProfile", "DeleteProfileW", "RegOpenKeyExW", "account_creation", "interactive_logon",
    "profile_create", "profile_path_validation", "profile_identity", "profile_registry_binding",
    "fixture_staging", "profile_logon_process_creation", "child_execution",
    "cleanup_process_exit", "cleanup_process_handles", "cleanup_job_handle",
    "cleanup_logon_token", "cleanup_creation_state", "cleanup_account_identity",
    "cleanup_profile_proof", "cleanup_profile_path", "cleanup_profile_identity",
    "cleanup_profile_deletion", "cleanup_account_deletion", "cleanup_account_absence",
    "cleanup_fixture", "cleanup_fixture_absence",
})


def plain_value(data: object, key: str) -> object:
    """Do not dispatch subclass methods or hostile dictionary-key comparisons."""
    if type(data) is not dict:
        return None
    try:
        return data.get(key)
    except BaseException:  # noqa: BLE001 - diagnostic attributes are untrusted
        return None


def directory_state(path: Path, identities: dict, *, capture: bool = False) -> dict:
    """Check ancestors top-down without following the entry being inspected.

    These path-based observations narrow replacement races; they are not atomic.
    Never inspect a descendant after an ancestor is absent, unreadable or changed.
    """
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            return {"state": "absent"}
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
            raise NativeError("reparse_path")
        identity = (info.st_dev, info.st_ino)
        if not stat.S_ISDIR(info.st_mode) or (
                part in identities and identities[part] != identity) or (
                not capture and part not in identities):
            raise NativeError("profile_identity_changed")
        identities[part] = identity
    return {"state": "present"}


def query_error_state(error: BaseException) -> dict:
    """Only numeric OS failure fields can accompany a static residual state."""
    detail = Native.diagnostic(error, "cleanup_profile_deletion")
    return {"state": "query_error", **{key: detail[key] for key in ("winerror", "errno")
                                      if key in detail}}


class SidAndAttributes(C.Structure):
    _fields_ = [("sid", C.c_void_p), ("attributes", W.DWORD)]


class Startup(C.Structure):
    _fields_ = [
        ("cb", W.DWORD), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR),
        ("title", W.LPWSTR), ("x", W.DWORD), ("y", W.DWORD), ("width", W.DWORD),
        ("height", W.DWORD), ("chars_x", W.DWORD), ("chars_y", W.DWORD),
        ("fill", W.DWORD), ("flags", W.DWORD), ("show", W.WORD), ("cb2", W.WORD),
        ("reserved2", C.c_void_p), ("stdin", W.HANDLE), ("stdout", W.HANDLE),
        ("stderr", W.HANDLE),
    ]


class ProcessInfo(C.Structure):
    _fields_ = [("process", W.HANDLE), ("thread", W.HANDLE),
                ("pid", W.DWORD), ("tid", W.DWORD)]


class User1(C.Structure):
    _fields_ = [
        ("name", W.LPWSTR), ("password", W.LPWSTR), ("age", W.DWORD),
        ("privilege", W.DWORD), ("home", W.LPWSTR), ("comment", W.LPWSTR),
        ("flags", W.DWORD), ("script", W.LPWSTR),
    ]


class User23(C.Structure):
    _fields_ = [("name", W.LPWSTR), ("full", W.LPWSTR), ("comment", W.LPWSTR),
                ("flags", W.DWORD), ("sid", C.c_void_p)]


class BasicLimit(C.Structure):
    _fields_ = [
        ("process_time", C.c_longlong), ("job_time", C.c_longlong),
        ("flags", W.DWORD), ("min_ws", C.c_size_t), ("max_ws", C.c_size_t),
        ("active", W.DWORD), ("affinity", C.c_size_t),
        ("priority", W.DWORD), ("scheduling", W.DWORD),
    ]


class ExtendedLimit(C.Structure):
    _fields_ = [("basic", BasicLimit), ("io", C.c_ulonglong * 6),
                ("memory", C.c_size_t * 4)]


class Native:
    """Explicit native calls; callers own identity and lifecycle decisions."""

    @staticmethod
    def diagnostic(error: BaseException, operation: str) -> dict:
        """Project only allowlisted labels and bounded integers, never exception text/args."""
        detail = {"code": "os_error" if isinstance(error, OSError) else "unclassified_failure",
                  "operation": operation if operation in DIAGNOSTIC_OPERATIONS else "unknown"}
        try:
            data = vars(error)
        except BaseException:  # noqa: BLE001 - exception attributes are untrusted
            data = {}
        if type(data) is dict:
            for key, allowed in (("code", DIAGNOSTIC_CODES),
                                 ("operation", DIAGNOSTIC_OPERATIONS)):
                value = plain_value(data, key)
                if type(value) is str and value in allowed:
                    detail[key] = value
        fields = ("hresult", "winerror", "errno") if isinstance(error, NativeError) else (
            ("winerror", "errno") if isinstance(error, OSError) else ())
        for key in fields:
            try:
                value = getattr(error, key, None)
            except BaseException:  # noqa: BLE001 - never log hostile attribute access
                value = None
            if type(value) is int and 0 <= value <= 0xFFFFFFFF:
                detail[key] = value
        residual = plain_value(data, "residual") if isinstance(error, NativeError) else None
        if type(residual) is dict:
            projected = {}
            for label in RESIDUAL_LABELS:
                item = plain_value(residual, label)
                if type(item) is not dict:
                    continue
                state = plain_value(item, "state")
                if type(state) is not str or state not in {"present", "absent", "query_error"}:
                    continue
                projected[label] = {"state": state}
                for key in ("winerror", "errno"):
                    value = plain_value(item, key)
                    if type(value) is int and 0 <= value <= 0xFFFFFFFF:
                        projected[label][key] = value
            if projected:
                detail["residual"] = projected
        return detail

    def __init__(self) -> None:
        if os.name != "nt":
            raise NativeError("windows_required")
        self.libs = {name: C.WinDLL(name, use_last_error=True)
                     for name in ("kernel32", "advapi32", "netapi32", "userenv",
                                  "iphlpapi")}

    def call(self, lib: str, name: str, result: object, types: list, *args: object) -> object:
        fn = getattr(self.libs[lib], name)
        fn.restype, fn.argtypes = result, types
        return fn(*args)

    def yes(self, value: object) -> None:
        if not value:
            raise NativeError("native_api_failed")

    def close(self, handle: object) -> None:
        if handle:
            self.yes(self.call("kernel32", "CloseHandle", W.BOOL, [W.HANDLE], handle))

    def sid_text(self, sid: object) -> str:
        text = W.LPWSTR()
        self.yes(self.call("advapi32", "ConvertSidToStringSidW", W.BOOL,
                          [C.c_void_p, C.POINTER(W.LPWSTR)], sid, C.byref(text)))
        try:
            return str(text.value)
        finally:
            self.call("kernel32", "LocalFree", C.c_void_p, [C.c_void_p], text)

    def token(self, process: object = None) -> dict:
        token = W.HANDLE()
        process = process or self.call("kernel32", "GetCurrentProcess", W.HANDLE, [])
        self.yes(self.call("advapi32", "OpenProcessToken", W.BOOL,
                          [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)],
                          process, 8, C.byref(token)))
        try:
            return self.token_info(token)
        finally:
            self.close(token)

    def token_info(self, token: object) -> dict:
        def info(kind: int) -> C.Array:
            size = W.DWORD()
            args = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
            self.call("advapi32", "GetTokenInformation", W.BOOL, args,
                      token, kind, None, 0, C.byref(size))
            if not 0 < size.value <= 65536:
                raise NativeError("token_size_invalid")
            buf = C.create_string_buffer(size.value)
            self.yes(self.call("advapi32", "GetTokenInformation", W.BOOL, args,
                              token, kind, buf, size.value, C.byref(size)))
            return buf
        user, groups, integrity = info(1), info(2), info(25)
        count = W.DWORD.from_buffer(groups).value
        offset = (C.sizeof(W.DWORD) + C.alignment(SidAndAttributes) - 1)
        offset -= offset % C.alignment(SidAndAttributes)
        if count > 1024 or offset + count * C.sizeof(SidAndAttributes) > len(groups):
            raise NativeError("token_groups_invalid")
        values = (SidAndAttributes * count).from_buffer(groups, offset)
        return {
            "sid": self.sid_text(SidAndAttributes.from_buffer(user).sid),
            "groups": [{"sid": self.sid_text(v.sid), "attributes": v.attributes}
                       for v in values],
            "elevated": bool(W.DWORD.from_buffer(info(20)).value),
            "elevation_type": W.DWORD.from_buffer(info(18)).value,
            "integrity": self.sid_text(SidAndAttributes.from_buffer(integrity).sid),
            "token_type": W.DWORD.from_buffer(info(8)).value,
        }

    def preflight(self) -> dict:
        return self.token()

    def account(self, name: str) -> dict | None:
        buf = C.c_void_p()
        code = self.call("netapi32", "NetUserGetInfo", W.DWORD,
                         [W.LPCWSTR, W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p)],
                         None, name, 23, C.byref(buf))
        if code == 2221:
            return None
        if code:
            raise NativeError("account_query_failed")
        try:
            data = C.cast(buf, C.POINTER(User23)).contents
            return {"name": data.name, "sid": self.sid_text(data.sid),
                    "comment": data.comment}
        finally:
            self.call("netapi32", "NetApiBufferFree", W.DWORD, [C.c_void_p], buf)

    def add_account(self, name: str, password: C.Array, marker: str) -> None:
        user = User1(name, C.cast(password, W.LPWSTR), 0, 1, None, marker, 0x201, None)
        error = W.DWORD()
        code = self.call("netapi32", "NetUserAdd", W.DWORD,
                         [W.LPCWSTR, W.DWORD, C.c_void_p, C.POINTER(W.DWORD)],
                         None, 1, C.byref(user), C.byref(error))
        if code:
            raise NativeError("account_creation_failed")

    def logon(self, name: str, password: C.Array) -> object:
        token = W.HANDLE()
        self.yes(self.call("advapi32", "LogonUserW", W.BOOL,
                          [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.DWORD, W.DWORD,
                           C.POINTER(W.HANDLE)], name, ".", password, 2, 0, C.byref(token)))
        return token

    def create_profile(self, name: str, sid: str) -> Path:
        buf = C.create_unicode_buffer(260)
        code = self.call("userenv", "CreateProfile", C.c_long,
                         [W.LPCWSTR, W.LPCWSTR, W.LPWSTR, W.DWORD],
                         sid, name, buf, len(buf))
        # Only S_OK proves creation. Existing profiles return
        # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS); never adopt them.
        if code != 0:
            raise NativeError("new_profile_required", operation="CreateProfile",
                              hresult=code & 0xFFFFFFFF)
        return Path(buf.value)

    def profile_path(self, sid: str, *, missing: bool = False) -> Path | None:
        import winreg
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + sid
        try:
            handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
        except OSError as error:
            code = getattr(error, "winerror", None)
            if missing and type(code) is int and code == 2:
                return None  # Only absence at key-open proves no ProfileList registration.
            raise
        with handle:
            value, kind = winreg.QueryValueEx(handle, "ProfileImagePath")
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or type(value) is not str or not value:
            raise NativeError("profile_registration_invalid")
        return Path(os.path.expandvars(value))

    def loaded_profile(self, sid: str) -> bool:
        import winreg
        try:
            handle = winreg.OpenKey(winreg.HKEY_USERS, sid)
        except OSError as error:
            code = getattr(error, "winerror", None)
            if type(code) is int and code == 2:  # ERROR_FILE_NOT_FOUND only.
                return False
            raise NativeError("profile_hive_query_failed", operation="RegOpenKeyExW",
                              winerror=code, errno=error.errno) from None
        with handle:
            return True

    def protect(self, path: Path, owner: str, grants: dict[str, str]) -> None:
        descriptor = C.c_void_p()
        sddl = "O:" + owner + "D:P" + "".join(
            f"(A;OICI;{rights};;;{sid})" for sid, rights in grants.items())
        self.yes(self.call("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                          W.BOOL, [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p],
                          sddl, 1, C.byref(descriptor), None))
        try:
            self.yes(self.call("advapi32", "SetFileSecurityW", W.BOOL,
                              [W.LPCWSTR, W.DWORD, C.c_void_p],
                              str(path), 0x80000005, descriptor))
        finally:
            self.call("kernel32", "LocalFree", C.c_void_p, [C.c_void_p], descriptor)

    def launch(self, name: str, password: C.Array, argv: list[str],
               env: dict[str, str], cwd: Path) -> ProcessInfo:
        command = subprocess.list2cmdline(argv)
        if len(command) >= 1024:
            raise NativeError("command_too_long")
        block = C.create_unicode_buffer("\0".join(
            f"{k}={v}" for k, v in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0")
        startup, result = Startup(), ProcessInfo()
        startup.cb, startup.flags, startup.show = C.sizeof(startup), 1, 0
        self.yes(self.call("advapi32", "CreateProcessWithLogonW", W.BOOL,
                          [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.DWORD, W.LPCWSTR,
                           W.LPWSTR, W.DWORD, C.c_void_p, W.LPCWSTR,
                           C.POINTER(Startup), C.POINTER(ProcessInfo)],
                          name, ".", password, 1, argv[0], C.create_unicode_buffer(command),
                          0x08000404, block, str(cwd), C.byref(startup), C.byref(result)))
        return result

    def job(self, process: object) -> object:
        job = self.call("kernel32", "CreateJobObjectW", W.HANDLE,
                        [C.c_void_p, W.LPCWSTR], None, None)
        self.yes(job)
        try:
            limits = ExtendedLimit()
            limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway.
            self.yes(self.call("kernel32", "SetInformationJobObject", W.BOOL,
                              [W.HANDLE, C.c_int, C.c_void_p, W.DWORD],
                              job, 9, C.byref(limits), C.sizeof(limits)))
            self.yes(self.call("kernel32", "AssignProcessToJobObject", W.BOOL,
                              [W.HANDLE, W.HANDLE], job, process))
            return job
        except BaseException:
            self.close(job)
            raise

    def resume(self, thread: object) -> None:
        if self.call("kernel32", "ResumeThread", W.DWORD, [W.HANDLE], thread) == 0xFFFFFFFF:
            raise NativeError("resume_failed")

    def wait(self, process: object, milliseconds: int) -> bool:
        result = self.call("kernel32", "WaitForSingleObject", W.DWORD,
                           [W.HANDLE, W.DWORD], process, milliseconds)
        if result not in (0, 258):
            raise NativeError("process_wait_failed")
        return result == 0

    def exit_code(self, process: object) -> int:
        code = W.DWORD()
        self.yes(self.call("kernel32", "GetExitCodeProcess", W.BOOL,
                          [W.HANDLE, C.POINTER(W.DWORD)], process, C.byref(code)))
        return code.value

    def terminate(self, handle: object, *, job: bool) -> None:
        name = "TerminateJobObject" if job else "TerminateProcess"
        self.yes(self.call("kernel32", name, W.BOOL, [W.HANDLE, W.DWORD], handle, 197))

    def job_empty(self, job: object, timeout: float = 10) -> bool:
        end = time.monotonic() + timeout
        while True:
            counts = C.create_string_buffer(48)
            self.yes(self.call("kernel32", "QueryInformationJobObject", W.BOOL,
                              [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p],
                              job, 1, counts, len(counts), None))
            if struct.unpack_from("I", counts, 40)[0] == 0:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.05)

    def runtime_handle(self, port: int, sid: str, image: Path) -> object:
        needed = W.DWORD()
        args = [C.c_void_p, C.POINTER(W.DWORD), W.BOOL, W.DWORD, C.c_int, W.DWORD]
        self.call("iphlpapi", "GetExtendedTcpTable", W.DWORD, args,
                  None, C.byref(needed), False, 2, 3, 0)
        if not 4 <= needed.value <= 8 * 1024 * 1024:
            raise NativeError("listener_table_invalid")
        buf = C.create_string_buffer(needed.value)
        if self.call("iphlpapi", "GetExtendedTcpTable", W.DWORD, args,
                     buf, C.byref(needed), False, 2, 3, 0):
            raise NativeError("listener_query_failed")
        count = struct.unpack_from("I", buf)[0]
        if 4 + count * 24 > len(buf):
            raise NativeError("listener_table_invalid")
        pids = [row[5] for row in (struct.unpack_from("6I", buf, 4 + i * 24)
                for i in range(count)) if row[0] == 2 and
                socket.inet_ntoa(struct.pack("I", row[1])) == "127.0.0.1" and
                socket.ntohs(row[2] & 0xFFFF) == port]
        if len(pids) != 1:
            raise NativeError("runtime_listener_not_unique")
        handle = self.call("kernel32", "OpenProcess", W.HANDLE,
                           [W.DWORD, W.BOOL, W.DWORD], 0x101000, False, pids[0])
        self.yes(handle)
        try:
            size, name = W.DWORD(32768), C.create_unicode_buffer(32768)
            self.yes(self.call("kernel32", "QueryFullProcessImageNameW", W.BOOL,
                              [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)],
                              handle, 0, name, C.byref(size)))
            if self.token(handle)["sid"] != sid or Path(name.value).resolve() != image.resolve():
                raise NativeError("runtime_identity_mismatch")
            return handle
        except BaseException:
            self.close(handle)
            raise

    def delete_profile(self, sid: str, profile: Path, *, owned_work: Path | None = None) -> None:
        deadline = time.monotonic() + 10
        while self.loaded_profile(sid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.profile_path(sid) != profile or self.loaded_profile(sid):
            raise NativeError("profile_cleanup_unproven")
        if not profile.is_absolute() or str(profile).startswith(("\\\\", "//")) or ".." in profile.parts:
            raise NativeError("local_path_required")
        locations = {}
        if owned_work is not None:
            suffix = owned_work.name.removeprefix("decisionmesh-standard-user-")
            if (owned_work.parent != profile / "AppData/Local"
                    or owned_work.name != "decisionmesh-standard-user-" + suffix
                    or len(suffix) != 32 or any(c not in "0123456789abcdef" for c in suffix)):
                raise NativeError("owned_work_path_invalid")
            locations = {"owned_work": owned_work, "user_data": owned_work / "user-data",
                         "environment": owned_work / "environment"}
        identities = {}
        if directory_state(profile, identities, capture=True)["state"] != "present":
            raise NativeError("profile_cleanup_unproven")
        for path in locations.values():
            try:
                directory_state(path, identities, capture=True)
            except (OSError, NativeError):
                pass  # Diagnostic uncertainty never expands deletion authority.
        # Best-effort descendant baselines must not hide a changed profile ancestor.
        if directory_state(profile, identities)["state"] != "present":
            raise NativeError("profile_cleanup_unproven")
        if not self.call("userenv", "DeleteProfileW", W.BOOL,
                         [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR], sid, str(profile), None):
            code = C.get_last_error()
            raise NativeError("profile_delete_failed", operation="DeleteProfileW", winerror=code)
        deadline = time.monotonic() + 10
        while True:
            residual, failure = {}, None
            try:
                residual["profile_root"] = directory_state(profile, identities)
            except (OSError, NativeError) as error:
                residual["profile_root"] = query_error_state(error)
                code = self.diagnostic(error, "cleanup_profile_deletion")["code"]
                failure = code if code in DIAGNOSTIC_CODES else "profile_observation_failed"
            try:
                registered = self.profile_path(sid, missing=True)
                residual["profile_registry"] = {"state": "absent" if registered is None else "present"}
                if registered is not None and registered != profile:
                    failure = "profile_binding_mismatch"
            except (OSError, NativeError) as error:
                residual["profile_registry"] = query_error_state(error)
                failure = failure or "profile_observation_failed"
            if all(item["state"] == "absent" for item in residual.values()):
                return
            remaining = deadline - time.monotonic()
            if failure or remaining <= 0:
                for label, path in locations.items():
                    try:
                        residual[label] = directory_state(path, identities)
                    except (OSError, NativeError) as error:
                        residual[label] = query_error_state(error)
                code = failure or ("profile_delete_not_observed"
                                   if residual["profile_root"]["state"] == "present"
                                   else "profile_registration_remains")
                raise NativeError(code, operation="cleanup_profile_deletion", residual=residual)
            time.sleep(min(0.05, remaining))

    def delete_account(self, name: str, *, expected_sid: str, expected_marker: str) -> None:
        expected = {"name": name, "sid": expected_sid, "comment": expected_marker}
        if self.account(name) != expected:
            raise NativeError("account_cleanup_identity_changed")
        # NetUserDel is name-only: this fresh check narrows the race, but is not atomic.
        if self.call("netapi32", "NetUserDel", W.DWORD,
                     [W.LPCWSTR, W.LPCWSTR], None, name):
            raise NativeError("account_delete_failed")
