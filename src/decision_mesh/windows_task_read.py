"""Bounded read-only Task Scheduler COM query, with lossless Unicode IPC."""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

MAX_XML_BYTES = 32768
MAX_REPLY_BYTES = MAX_XML_BYTES * 6 + 2048
_NAME_FORBIDDEN = set("\\/\x00\r\n")


class TaskReadError(RuntimeError):
    """Fixed diagnostic; no task XML, account name or external COM description."""


class _ComFailure(Exception):
    def __init__(self, code: int):
        self.code = code & 0xFFFFFFFF


class _GUID(ctypes.Structure):
    _fields_ = [("data1", ctypes.c_uint32), ("data2", ctypes.c_uint16),
                ("data3", ctypes.c_uint16), ("data4", ctypes.c_ubyte * 8)]

    @classmethod
    def of(cls, text: str):
        return cls.from_buffer_copy(uuid.UUID(text).bytes_le)


class _Payload(ctypes.Union):
    _fields_ = [("pointer", ctypes.c_void_p), ("record", ctypes.c_void_p * 2)]


class _Variant(ctypes.Structure):
    _anonymous_ = ("payload",)
    _fields_ = [("vt", ctypes.c_uint16), ("r1", ctypes.c_uint16),
                ("r2", ctypes.c_uint16), ("r3", ctypes.c_uint16), ("payload", _Payload)]


class _Params(ctypes.Structure):
    _fields_ = [("values", ctypes.POINTER(_Variant)), ("named", ctypes.POINTER(ctypes.c_int32)),
                ("count", ctypes.c_uint32), ("named_count", ctypes.c_uint32)]


class _ExceptionInfo(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
                ("source", ctypes.c_void_p), ("description", ctypes.c_void_p),
                ("helpfile", ctypes.c_void_p), ("helpcontext", ctypes.c_uint32),
                ("reserved_pointer", ctypes.c_void_p), ("deferred", ctypes.c_void_p),
                ("scode", ctypes.c_int32)]


def _validate_name(name: str) -> None:
    if not isinstance(name, str) or not 1 <= len(name) <= 238 or any(
        char in _NAME_FORBIDDEN or ord(char) < 32 or char in "*?" for char in name
    ) or name in {".", ".."}:
        raise TaskReadError("windows_task_name_invalid")


def _check(code: int) -> None:
    if code < 0:
        raise _ComFailure(code)


def _call(pointer, index, types, *args):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    method = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, *types)(table[index])
    return method(pointer, *args)


class _Dispatch:
    """Only Connect/GetFolder/GetTask/Xml are invoked by the query below."""
    def __init__(self):
        self.ole = ctypes.WinDLL("ole32")
        self.auto = ctypes.WinDLL("oleaut32")
        self.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.ole.CoInitializeEx.restype = ctypes.c_int32
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoCreateInstance.argtypes = [ctypes.POINTER(_GUID), ctypes.c_void_p,
                                             ctypes.c_uint32, ctypes.POINTER(_GUID),
                                             ctypes.POINTER(ctypes.c_void_p)]
        self.ole.CoCreateInstance.restype = ctypes.c_int32
        self.auto.SysAllocString.argtypes = [ctypes.c_wchar_p]
        self.auto.SysAllocString.restype = ctypes.c_void_p
        self.auto.SysFreeString.argtypes = [ctypes.c_void_p]
        self.auto.SysStringLen.argtypes = [ctypes.c_void_p]
        self.auto.SysStringLen.restype = ctypes.c_uint32
        self.auto.VariantClear.argtypes = [ctypes.POINTER(_Variant)]

    def invoke(self, pointer, member: str, args: tuple[str, ...] = (), *, kind="empty"):
        null = _GUID()
        names = (ctypes.c_wchar_p * 1)(member)
        dispid = ctypes.c_int32()
        _check(_call(pointer, 5, [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_wchar_p),
                                 ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int32)],
                     ctypes.byref(null), names, 1, 0, ctypes.byref(dispid)))
        values = (_Variant * len(args))()
        result, error = _Variant(), _ExceptionInfo()
        try:
            for value, text in zip(values, reversed(args), strict=True):
                value.vt = 8  # VT_BSTR: ownership released through VariantClear
                value.pointer = self.auto.SysAllocString(text)
                if not value.pointer:
                    raise MemoryError()
            params = _Params(values, None, len(args), 0)
            code = _call(pointer, 6, [ctypes.c_int32, ctypes.POINTER(_GUID), ctypes.c_uint32,
                                     ctypes.c_uint16, ctypes.POINTER(_Params),
                                     ctypes.POINTER(_Variant), ctypes.POINTER(_ExceptionInfo),
                                     ctypes.POINTER(ctypes.c_uint32)],
                         dispid, ctypes.byref(null), 0, 2 if member == "Xml" else 1,
                         ctypes.byref(params), ctypes.byref(result), ctypes.byref(error), None)
            if code & 0xFFFFFFFF == 0x80020009 and error.scode:  # DISP_E_EXCEPTION
                code = error.scode
            _check(code)
            if kind == "dispatch" and result.vt == 9 and result.pointer:
                pointer = ctypes.c_void_p(result.pointer)
                result.vt = 0  # transfer this reference to the query's release list
                return pointer
            if kind == "text" and result.vt == 8 and result.pointer:
                units = self.auto.SysStringLen(result.pointer)
                if units * 2 > MAX_XML_BYTES:
                    raise TaskReadError("windows_task_xml_capacity")
                return ctypes.wstring_at(result.pointer, units)
            if kind != "empty" or result.vt != 0:
                raise TaskReadError("windows_task_com_result_invalid")
            return None
        finally:
            for value in values:
                self.auto.VariantClear(ctypes.byref(value))
            self.auto.VariantClear(ctypes.byref(result))
            for pointer in (error.source, error.description, error.helpfile):
                if pointer:
                    self.auto.SysFreeString(pointer)


def _current_account() -> str:
    """Query only the invoking token's SAM-compatible Unicode account name."""
    api = ctypes.WinDLL("secur32", use_last_error=True)
    api.GetUserNameExW.argtypes = [ctypes.c_int32, ctypes.c_wchar_p,
                                 ctypes.POINTER(ctypes.c_uint32)]
    api.GetUserNameExW.restype = ctypes.c_ubyte
    size = ctypes.c_uint32()
    api.GetUserNameExW(2, None, ctypes.byref(size))  # NameSamCompatible
    if not 1 < size.value <= 32768:
        raise TaskReadError("windows_current_account_unavailable")
    buffer = ctypes.create_unicode_buffer(size.value)
    if not api.GetUserNameExW(2, buffer, ctypes.byref(size)) or not buffer.value:
        raise TaskReadError("windows_current_account_unavailable")
    return buffer.value


def _query_local(name: str) -> tuple[str, str] | None:
    """Run only in the bounded child; no caller-controlled server or credentials."""
    _validate_name(name)
    com = _Dispatch()
    initialized = False
    pointers = []
    try:
        _check(com.ole.CoInitializeEx(None, 2))
        initialized = True
        service = ctypes.c_void_p()
        clsid = _GUID.of("0f87369f-a4e5-4cfc-bd3e-73e6154572dd")
        iid = _GUID.of("00020400-0000-0000-c000-000000000046")  # IDispatch
        _check(com.ole.CoCreateInstance(ctypes.byref(clsid), None, 1,
                                        ctypes.byref(iid), ctypes.byref(service)))
        pointers.append(service)
        com.invoke(service, "Connect")  # empty parameters mean local/current token
        folder = com.invoke(service, "GetFolder", ("\\",), kind="dispatch")
        pointers.append(folder)
        try:
            task = com.invoke(folder, "GetTask", (name,), kind="dispatch")
        except _ComFailure as exc:
            if exc.code == 0x80070002:  # exact GetTask ERROR_FILE_NOT_FOUND only
                return None
            raise
        pointers.append(task)
        return com.invoke(task, "Xml", kind="text"), _current_account()
    finally:
        for pointer in reversed(pointers):
            if pointer:
                _call(pointer, 2, [])  # IUnknown.Release
        if initialized:
            com.ole.CoUninitialize()


def _main(name: str) -> None:
    try:
        observed = _query_local(name)
        reply = {"status": "absent"} if observed is None else {
            "status": "present", "xml": observed[0], "account": observed[1]}
    except Exception:  # noqa: BLE001 - never emit COM descriptions or private task content on failure
        reply = {"status": "error"}
    print(json.dumps(reply, ensure_ascii=True))


def read_task_document(name: str) -> tuple[str, str] | None:
    """Query one exact root task, with 15-second isolation and ASCII JSON IPC."""
    _validate_name(name)
    if os.name != "nt":
        raise TaskReadError("windows_required")
    code = """import json, sys
from pathlib import Path
try:
    origin = Path(sys.argv[1]).resolve(strict=True)
    member = "decision_mesh/windows_task_read.py"
    expected = origin / member
    limit = 131072
    if origin.is_dir():
        target = expected.resolve(strict=True)
        if not target.is_relative_to(origin) or not target.is_file():
            raise ImportError("reader_origin_mismatch")
        with target.open("rb") as stream:
            source = stream.read(limit + 1)
    elif origin.is_file():
        from zipfile import ZipFile
        with ZipFile(origin) as archive:
            matches = [entry for entry in archive.infolist() if entry.filename == member]
            if len(matches) != 1 or not 0 < matches[0].file_size <= limit:
                raise ImportError("reader_origin_mismatch")
            with archive.open(matches[0]) as stream:
                source = stream.read(limit + 1)
    else:
        raise ImportError("reader_origin_mismatch")
    if not 0 < len(source) <= limit:
        raise ImportError("reader_origin_mismatch")
    # The reader is stdlib-only. Never import its parent package or search for a fallback.
    namespace = {"__name__": "_decisionmesh_task_reader", "__file__": str(expected),
                 "__package__": None}
    exec(compile(source, str(expected), "exec", dont_inherit=True), namespace)
    namespace["_main"](sys.argv[2])
except Exception:
    print(json.dumps({"status": "error"}))
"""
    try:
        process = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).parents[1]), name],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if process.returncode or len(process.stdout) > MAX_REPLY_BYTES or process.stderr:
            raise ValueError()
        reply = json.loads(process.stdout.decode("ascii", errors="strict"))
        if reply == {"status": "absent"}:
            return None
        if not isinstance(reply, dict) or set(reply) != {"status", "xml", "account"}:
            raise ValueError()
        xml, account = reply["xml"], reply["account"]
        if reply["status"] != "present" or not isinstance(xml, str) or not isinstance(account, str):
            raise ValueError()
        if not 0 < len(xml.encode("utf-16-le", errors="strict")) <= MAX_XML_BYTES:
            raise ValueError()
        if not 0 < len(account) <= 32768 or "\x00" in xml or "\x00" in account:
            raise ValueError()
        return xml, account
    except Exception:  # noqa: BLE001 - fixed failure, no unknown failure is interpreted as absence
        raise TaskReadError("windows_task_query_failed") from None
