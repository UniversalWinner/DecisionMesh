"""Native Windows API adapter. No calls run on import; tests replace OS boundaries."""

from __future__ import annotations

import csv
import ctypes
import io
import os
import re
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .capture import assert_owner_only, atomic_write_owner_only
from .windows_task_read import TaskReadError, read_task_document

MAX_METADATA = 32768
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


class IntegrationError(RuntimeError):
    pass


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def of(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)


def current_user_sid() -> str:
    """Read the invoking user's SID through the installed Windows identity tool."""
    if os.name != "nt":
        raise IntegrationError("windows_required")
    try:
        executable = validate_integration_path(
            Path(os.environ.get("SystemRoot", "")) / "System32" / "whoami.exe", exists=True
        )
        result = subprocess.run(
            [str(executable), "/user", "/fo", "csv", "/nh"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode or len(result.stdout) > 4096:
            raise ValueError()
        rows = list(csv.reader(io.StringIO(result.stdout.decode("utf-8", errors="replace"))))
        if (
            len(rows) != 1
            or len(rows[0]) != 2
            or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+", rows[0][1])
        ):
            raise ValueError()
        return rows[0][1]
    except Exception:  # noqa: BLE001 - fixed OS diagnostic only
        raise IntegrationError("current_user_identity_unavailable") from None


def current_user_programs_dir() -> Path:
    """Query FOLDERID_Programs for the current token, respecting folder redirection."""
    return _current_user_folder("a77f5d77-2e2b-44c3-a6a2-aba601054a51", "user_start_menu_unavailable")


def current_user_local_appdata_dir() -> Path:
    """Canonical coordination root, independent of data-dir/environment overrides."""
    return _current_user_folder("f1b32785-6fba-4fcf-9d55-7b8e7f157091", "user_local_appdata_unavailable")


def _current_user_folder(folder_id: str, failure: str) -> Path:
    if os.name != "nt":
        raise IntegrationError("windows_required")
    path_pointer = ctypes.c_void_p()
    ole = None
    try:
        shell = ctypes.WinDLL("shell32")
        ole = ctypes.WinDLL("ole32")
        ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole.CoTaskMemFree.restype = None
        shell.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(_GUID),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        shell.SHGetKnownFolderPath.restype = ctypes.c_long
        folder = _GUID.of(folder_id)
        # Flags=0 never creates a folder. NULL token selects the current user.
        result = shell.SHGetKnownFolderPath(
            ctypes.byref(folder), 0, None, ctypes.byref(path_pointer)
        )
        if result < 0 or not path_pointer.value:
            raise ValueError()
        path = validate_integration_path(ctypes.wstring_at(path_pointer.value))
        if not path.is_dir():
            raise ValueError()
        return path
    except Exception:  # noqa: BLE001 - fixed OS diagnostic only
        raise IntegrationError(failure) from None
    finally:
        if ole is not None and path_pointer.value:
            ole.CoTaskMemFree(path_pointer)


def validate_integration_path(path: Path | str, *, exists=False) -> Path:
    result = Path(path)
    if not result.is_absolute() or any(ord(c) < 32 or c == '"' for c in str(result)):
        raise IntegrationError("integration_path_invalid")
    for item in (result, *result.parents):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            raise IntegrationError("integration_path_unsafe")
    if exists and not result.is_file():
        raise IntegrationError("installed_entry_point_missing")
    return result.resolve(strict=False)


@dataclass(frozen=True)
class TaskSpec:
    name: str
    owner: str
    sid: str
    command: str
    arguments: str


@dataclass(frozen=True)
class ShortcutSpec:
    path: str
    owner: str
    command: str
    arguments: str
    show_command: int = 7


def task_xml(spec: TaskSpec) -> bytes:
    root = ET.Element("Task", {"version": "1.2", "xmlns": TASK_NS})
    registration = ET.SubElement(root, "RegistrationInfo")
    ET.SubElement(registration, "Author").text = spec.sid
    ET.SubElement(registration, "Description").text = spec.owner
    trigger = ET.SubElement(ET.SubElement(root, "Triggers"), "LogonTrigger")
    ET.SubElement(trigger, "Enabled").text = "true"
    ET.SubElement(trigger, "UserId").text = spec.sid
    principal = ET.SubElement(ET.SubElement(root, "Principals"), "Principal", {"id": "User"})
    ET.SubElement(principal, "UserId").text = spec.sid
    ET.SubElement(principal, "LogonType").text = "InteractiveToken"
    ET.SubElement(principal, "RunLevel").text = "LeastPrivilege"
    settings = ET.SubElement(root, "Settings")
    for key, value in {
        "MultipleInstancesPolicy": "IgnoreNew",
        "DisallowStartIfOnBatteries": "false",
        "StopIfGoingOnBatteries": "false",
        "StartWhenAvailable": "true",
        "Enabled": "true",
        "Hidden": "true",
        "ExecutionTimeLimit": "PT0S",
    }.items():
        ET.SubElement(settings, key).text = value
    action = ET.SubElement(ET.SubElement(root, "Actions", {"Context": "User"}), "Exec")
    ET.SubElement(action, "Command").text = spec.command
    ET.SubElement(action, "Arguments").text = spec.arguments
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def _task_semantics(element: ET.Element) -> tuple:
    """Preserve all behavior; sort only schema xs:all containers."""
    children = tuple(element)
    if (children and element.text and element.text.strip()) or (
        element.tail and element.tail.strip()
    ):
        raise ValueError("unexpected_task_text")
    semantics = tuple(_task_semantics(child) for child in children)
    unordered = {"Task", "RegistrationInfo", "Settings", "IdleSettings", "Principal", "Exec"}
    if element.tag in {f"{{{TASK_NS}}}{name}" for name in unordered}:
        semantics = tuple(sorted(semantics))
    return (
        element.tag,
        tuple(sorted(element.attrib.items())),
        "" if children else element.text or "",
        semantics,
    )


def _normalize_task(root: ET.Element, name: str, current_identity: tuple[str, str] | None) -> None:
    """Only equivalents observed on Windows and documented by the Scheduler schema."""
    ns = {"t": TASK_NS}
    tag = lambda value: f"{{{TASK_NS}}}{value}"
    for path, field, value in (
        ("t:Triggers/t:LogonTrigger", "Enabled", "true"),
        ("t:Principals/t:Principal", "RunLevel", "LeastPrivilege"),
        ("t:Settings", "Enabled", "true"),
    ):
        parent = root.find(path, ns)
        if parent is None:
            raise ValueError("missing_task_section")
        if parent.find(tag(field)) is None:
            default = ET.Element(tag(field))
            default.text = value
            parent.insert(0, default) if field == "Enabled" and path.endswith("LogonTrigger") else parent.append(default)
    registration = root.find("t:RegistrationInfo", ns)
    if registration is None:
        raise ValueError("missing_registration")
    uri = registration.find(tag("URI"))
    if uri is not None:
        expected = ET.Element(tag("URI"))
        expected.text = "\\" + name
        if _task_semantics(uri) != _task_semantics(expected):
            raise ValueError("unexpected_task_uri")
        registration.remove(uri)
    settings = root.find("t:Settings", ns)
    idle = settings.find(tag("IdleSettings"))
    if idle is not None:
        expected = ET.Element(tag("IdleSettings"))
        for field, value in (("StopOnIdleEnd", "true"), ("RestartOnIdle", "false")):
            ET.SubElement(expected, tag(field)).text = value
        if _task_semantics(idle) != _task_semantics(expected):
            raise ValueError("unexpected_idle_settings")
        settings.remove(idle)
    sid = root.findtext("t:Principals/t:Principal/t:UserId", namespaces=ns)
    trigger_user = root.find("t:Triggers/t:LogonTrigger/t:UserId", ns)
    if trigger_user is not None and trigger_user.text != sid:
        if current_identity is None or current_identity[0] != sid:
            raise ValueError("unverified_task_account")
        account = current_identity[1]
        alias = trigger_user.text
        # Never resolve a task-supplied domain. Unicode names require exact
        # spelling; case variants are qualified only for the ASCII account form.
        matches = isinstance(alias, str) and isinstance(account, str) and account and (
            alias == account or alias.isascii() and account.isascii() and alias.lower() == account.lower()
        )
        if not matches:
            raise ValueError("unverified_task_account")
        trigger_user.text = sid


def parse_task(
    name: str, raw: bytes | str, *, current_identity: tuple[str, str] | None = None
) -> TaskSpec:
    try:
        encoded = raw.encode("utf-16-le", errors="strict") if isinstance(raw, str) else raw
        folded = encoded.replace(b"\x00", b"").upper()
        if len(encoded) > MAX_METADATA or b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
            raise ValueError()
        root = ET.fromstring(raw)
        _normalize_task(root, name, current_identity)
        ns = {"t": TASK_NS}

        def val(path):
            return root.findtext(path, namespaces=ns)

        sid = val("t:Principals/t:Principal/t:UserId")
        if (
            root.tag != f"{{{TASK_NS}}}Task"
            or len(root.findall("t:Actions/*", ns)) != 1
            or len(root.findall("t:Triggers/*", ns)) != 1
            or len(root.findall("t:Principals/*", ns)) != 1
            or val("t:Principals/t:Principal/t:LogonType") != "InteractiveToken"
            or val("t:Principals/t:Principal/t:RunLevel") != "LeastPrivilege"
            or val("t:RegistrationInfo/t:Author") != sid
            or val("t:Triggers/t:LogonTrigger/t:UserId") != sid
            or val("t:Triggers/t:LogonTrigger/t:Enabled") != "true"
            or val("t:Settings/t:Hidden") != "true"
            or val("t:Settings/t:Enabled") != "true"
            or val("t:Settings/t:MultipleInstancesPolicy") != "IgnoreNew"
            or val("t:Settings/t:ExecutionTimeLimit") != "PT0S"
            or root.find("t:Actions", ns).get("Context") != "User"
            or root.find("t:Principals/t:Principal", ns).get("id") != "User"
        ):
            raise ValueError()
        values = (
            name,
            val("t:RegistrationInfo/t:Description"),
            sid,
            val("t:Actions/t:Exec/t:Command"),
            val("t:Actions/t:Exec/t:Arguments"),
        )
        if not all(isinstance(v, str) and v for v in values):
            raise ValueError()
        spec = TaskSpec(*values)
        if _task_semantics(root) != _task_semantics(ET.fromstring(task_xml(spec))):
            raise ValueError("unexpected_task_semantics")
        return spec
    except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
        raise IntegrationError("task_not_owned_or_invalid") from None


class NativeWindowsBackend:
    """No elevation, no shell invocation, bounded subprocesses, hidden windows."""

    def __init__(self, *, data_dir: Path):
        if os.name != "nt":
            raise IntegrationError("windows_required")
        self.data_dir = validate_integration_path(data_dir)
        self.schtasks = validate_integration_path(
            Path(os.environ.get("SystemRoot", "")) / "System32" / "schtasks.exe", exists=True
        )

    def _run(self, args) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [str(self.schtasks), *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=15,
                check=False,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise IntegrationError("windows_task_operation_failed") from None

    def read_task(self, name):
        try:
            observed = read_task_document(name)
        except TaskReadError:
            raise IntegrationError("windows_task_query_failed") from None
        if observed is None:
            return None
        xml, account = observed
        return parse_task(name, xml, current_identity=(current_user_sid(), account))

    def write_task(self, spec, *, replace, expected: TaskSpec | None = None):
        if replace != (expected is not None) or (expected is not None and expected.name != spec.name):
            raise IntegrationError("integration_expected_state_required")
        path = self.data_dir / ("task-" + uuid.uuid4().hex + ".xml")
        atomic_write_owner_only(path, task_xml(spec), max_bytes=MAX_METADATA)
        try:
            args = ["/Create", "/TN", spec.name, "/XML", str(path)]
            if replace:
                args.append("/F")
            # Preparing the XML may take time. Do not use the manager's earlier
            # observation to authorize replacement after that work.
            if self.read_task(spec.name) != expected:
                raise IntegrationError("foreign_or_modified_entry_preserved")
            if self._run(args).returncode:
                raise IntegrationError("windows_task_install_failed")
        finally:
            assert_owner_only(path)
            path.unlink()

    def remove_task(self, name, *, expected: TaskSpec):
        if not isinstance(expected, TaskSpec) or expected.name != name:
            raise IntegrationError("integration_expected_state_required")
        if self.read_task(name) != expected:
            raise IntegrationError("foreign_or_modified_entry_preserved")
        # Scheduler deletion is name-based: an independent external edit after
        # this final read cannot be made atomic with the delete API.
        if self._run(["/Delete", "/TN", name, "/F"]).returncode:
            raise IntegrationError("windows_task_remove_failed")

    def read_shortcut(self, path):
        path = validate_integration_path(path)
        return _shell_link(path) if path.exists() else None

    def write_shortcut(self, spec, *, expected: ShortcutSpec | None = None):
        path = validate_integration_path(spec.path)
        if expected is not None and expected.path != spec.path:
            raise IntegrationError("integration_expected_state_required")
        # The user Start Menu itself is Windows-managed; do not recursively
        # replace its ACLs. Only this exact file belongs to the integration.
        if not path.parent.is_dir():
            raise IntegrationError("user_start_menu_unavailable")
        # IPersistFile saves to this explicit path. A crash must not leave an
        # extra discoverable .lnk in Programs before canonical publication.
        fd, temporary = tempfile.mkstemp(prefix=".decisionmesh-", suffix=".tmp", dir=path.parent)
        os.close(fd)
        staged = Path(temporary)
        try:
            _shell_link(staged, spec)
            if self.read_shortcut(path) != expected:
                raise IntegrationError("foreign_or_modified_entry_preserved")
            if expected is None:
                # Publishing a new entry is exclusive even if another writer
                # creates it after our final absence check. Same-volume staging.
                os.link(staged, path)
            else:
                os.replace(staged, path)
        finally:
            validate_integration_path(staged).unlink(missing_ok=True)

    def remove_shortcut(self, path, *, expected: ShortcutSpec):
        path = validate_integration_path(path)
        if not isinstance(expected, ShortcutSpec) or expected.path != str(path):
            raise IntegrationError("integration_expected_state_required")
        if self.read_shortcut(path) != expected:
            raise IntegrationError("foreign_or_modified_entry_preserved")
        path.unlink()


def _shell_link(path: Path, spec: ShortcutSpec | None = None) -> ShortcutSpec | None:
    """Small Windows IShellLinkW/IPersistFile boundary, no extra dependency."""
    from ctypes import wintypes

    ole = ctypes.OleDLL("ole32")
    link = ctypes.c_void_p()
    persist = ctypes.c_void_p()
    initialized = False

    def call(pointer, index, argtypes, *args):
        table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        function = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(table[index])
        result = function(pointer, *args)
        if result < 0:
            raise IntegrationError("windows_shortcut_operation_failed")
        return result

    try:
        ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        result = ole.CoInitializeEx(None, 2)
        initialized = result in (0, 1)
        if not initialized:
            raise IntegrationError("windows_shortcut_com_unavailable")
        clsid = _GUID.of("00021401-0000-0000-c000-000000000046")
        iid = _GUID.of("000214f9-0000-0000-c000-000000000046")
        if (
            ole.CoCreateInstance(
                ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(link)
            )
            < 0
        ):
            raise IntegrationError("windows_shortcut_operation_failed")
        persist_iid = _GUID.of("0000010b-0000-0000-c000-000000000046")
        call(
            link,
            0,
            [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)],
            ctypes.byref(persist_iid),
            ctypes.byref(persist),
        )
        if spec:
            for index, value in ((20, spec.command), (11, spec.arguments), (7, spec.owner)):
                call(link, index, [wintypes.LPCWSTR], value)
            call(link, 15, [ctypes.c_int], spec.show_command)
            call(persist, 6, [wintypes.LPCWSTR, wintypes.BOOL], str(path), True)
            return None
        call(persist, 5, [wintypes.LPCWSTR, wintypes.DWORD], str(path), 0)
        command, arguments, owner = (ctypes.create_unicode_buffer(32768) for _ in range(3))
        call(
            link,
            3,
            [wintypes.LPWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            command,
            len(command),
            None,
            4,
        )
        call(link, 10, [wintypes.LPWSTR, ctypes.c_int], arguments, len(arguments))
        call(link, 6, [wintypes.LPWSTR, ctypes.c_int], owner, len(owner))
        show = ctypes.c_int()
        call(link, 14, [ctypes.POINTER(ctypes.c_int)], ctypes.byref(show))
        return ShortcutSpec(str(path), owner.value, command.value, arguments.value, show.value)
    except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
        raise IntegrationError("windows_shortcut_operation_failed") from None
    finally:
        for pointer in (persist, link):
            if pointer:
                call(pointer, 2, [])
        if initialized:
            ole.CoUninitialize()
