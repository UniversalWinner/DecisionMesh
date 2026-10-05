"""Opt-in, per-user Windows integration with reviewable plans and exact ownership.

No host configuration/trust is edited. Constructors/planners never register OS
entries. The apply boundary is explicit; build tests inject a fake OS backend.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .capture import (
    CaptureError,
    assert_owner_only,
    atomic_write_owner_only,
    ensure_spool_dir,
    owner_file_lock,
    parse_json,
)
from .windows_native import (
    MAX_METADATA,
    IntegrationError,
    NativeWindowsBackend,
    ShortcutSpec,
    TaskSpec,
    current_user_local_appdata_dir,
    current_user_programs_dir,
    current_user_sid,
    parse_task,
    task_xml,
    validate_integration_path,
)

__all__ = [
    "IntegrationError",
    "IntegrationPlan",
    "NativeWindowsBackend",
    "ShortcutSpec",
    "TaskSpec",
    "WindowsBackend",
    "WindowsIntegration",
    "build_current_user_integration",
    "parse_task",
    "proposed_hook_addition",
    "resolve_console_script",
    "task_xml",
]


def build_current_user_integration(data_dir: Path | str) -> WindowsIntegration:
    """Read-only factory. Native writes occur only through an explicit apply()."""
    directory = validate_integration_path(data_dir)
    return WindowsIntegration(
        data_dir=directory,
        programs_dir=current_user_programs_dir(),
        user_sid=current_user_sid(),
        backend=NativeWindowsBackend(data_dir=directory),
    )


def resolve_console_script() -> Path:
    from .runtime_control import RuntimeErrorCode, resolve_installed_console

    try:
        candidate = resolve_installed_console()
    except RuntimeErrorCode:
        raise IntegrationError("installed_entry_point_missing") from None
    result = validate_integration_path(candidate, exists=True)
    if result.name.lower() != "decisionmesh.exe":
        raise IntegrationError("installed_entry_point_invalid")
    return result


class WindowsBackend(Protocol):
    def read_task(self, name: str) -> TaskSpec | None: ...
    def write_task(self, spec: TaskSpec, *, replace: bool, expected: TaskSpec | None = None) -> None: ...
    def remove_task(self, name: str, *, expected: TaskSpec) -> None: ...
    def read_shortcut(self, path: Path) -> ShortcutSpec | None: ...
    def write_shortcut(self, spec: ShortcutSpec, *, expected: ShortcutSpec | None = None) -> None: ...
    def remove_shortcut(self, path: Path, *, expected: ShortcutSpec) -> None: ...


@dataclass(frozen=True)
class IntegrationPlan:
    """Opaque reviewed proposal; apply re-plans and checks every observed item."""

    operation: str
    autostart: bool
    shortcut: bool
    snapshot: str
    changes: tuple[str, ...]
    task_spec: TaskSpec | None
    shortcut_spec: ShortcutSpec | None
    launchers: tuple[tuple[str, str], ...]


def _launcher(owner: str, console: Path, data_dir: Path, command: str) -> str:
    # list2cmdline is Windows CRT quoting. VBScript doubles quotes, and Run's
    # window style 0 hides the console. Paths containing environment expansion
    # characters are refused because WScript.Shell expands percent sequences.
    args = subprocess.list2cmdline([str(console), command, "--data-dir", str(data_dir)])
    if "%" in args or any(ord(c) < 32 for c in args):
        raise IntegrationError("integration_path_invalid")
    escaped = args.replace('"', '""')
    return f'\' {owner}\r\nOption Explicit\r\nCreateObject("WScript.Shell").Run "{escaped}", 0, False\r\n'


class WindowsIntegration:
    """Apply only plans produced by this instance and explicitly selected options.

    Runtime obtains current user SID and Start Menu Programs path from Windows;
    it must not accept these values from source content. Existing entries require
    BOTH a private manifest and exact equality with its saved specification.
    Data deletion, credential deletion and native hook trust are separate actions.
    """

    def __init__(
        self,
        *,
        data_dir: Path,
        programs_dir: Path,
        user_sid: str,
        backend: WindowsBackend,
        console_resolver=resolve_console_script,
        windows_dir: Path | None = None,
    ):
        if not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+", user_sid):
            raise IntegrationError("current_user_sid_required")
        self.data_dir = validate_integration_path(data_dir)
        self.programs_dir = validate_integration_path(programs_dir)
        self.sid = user_sid
        suffix = hashlib.sha256(user_sid.encode()).hexdigest()[:16]
        self.owner = "DecisionMesh/v1/" + suffix
        self.task_name = "DecisionMesh-" + suffix
        self.shortcut_path = self.programs_dir / "Decision Mesh.lnk"
        self.manifest_path = self.data_dir / "windows-integration.json"
        self.backend = backend
        self._resolve = console_resolver
        self._windows_dir = windows_dir
        self._plans: dict[str, IntegrationPlan] = {}

    def _manifest(self) -> dict:
        if not self.manifest_path.exists():
            return {
                "owner": self.owner,
                "task": None,
                "shortcut": None,
                "launchers": {},
                "pending": None,
            }
        try:
            assert_owner_only(self.manifest_path)
            with self.manifest_path.open("rb") as handle:
                data = parse_json(handle.read(MAX_METADATA + 1), max_bytes=MAX_METADATA)
            if (
                set(data) != {"owner", "task", "shortcut", "launchers", "pending"}
                or data["owner"] != self.owner
            ):
                raise ValueError()
            if not isinstance(data["launchers"], dict) or set(data["launchers"]) - {"run", "open"}:
                raise ValueError()
            pending = data["pending"]
            if pending is not None and (
                not isinstance(pending, dict)
                or set(pending) != {"owner", "task", "shortcut", "launchers"}
                or pending["owner"] != self.owner
                or not isinstance(pending["launchers"], dict)
                or set(pending["launchers"]) - {"run", "open"}
            ):
                raise ValueError()
            return data
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise IntegrationError("integration_manifest_invalid") from None

    def _observed(self) -> tuple[dict, TaskSpec | None, ShortcutSpec | None, dict]:
        manifest = self._manifest()
        task = self.backend.read_task(self.task_name)
        shortcut = self.backend.read_shortcut(self.shortcut_path)
        pending = manifest["pending"] or {}
        for actual, key in ((task, "task"), (shortcut, "shortcut")):
            if actual is not None and (
                actual.owner != self.owner
                or asdict(actual) not in (manifest[key], pending.get(key))
            ):
                raise IntegrationError("foreign_or_modified_entry_preserved")
        launchers = {}
        for command in ("run", "open"):
            path = self.data_dir / f"launch-{command}.vbs"
            validate_integration_path(path)
            if path.exists():
                assert_owner_only(path)
                with path.open("rb") as handle:
                    raw = handle.read(MAX_METADATA + 1)
                try:
                    content = raw.decode("utf-16")
                except UnicodeError:
                    raise IntegrationError("owned_launcher_invalid") from None
                if len(raw) > MAX_METADATA or content not in (
                    manifest["launchers"].get(command),
                    pending.get("launchers", {}).get(command),
                ):
                    raise IntegrationError("foreign_or_modified_entry_preserved")
                launchers[command] = content
        return manifest, task, shortcut, launchers

    def _desired(self, autostart: bool, shortcut: bool) -> dict:
        desired = {"owner": self.owner, "task": None, "shortcut": None, "launchers": {}}
        if not (autostart or shortcut):
            return desired
        console = validate_integration_path(self._resolve(), exists=True)
        if console.name.lower() != "decisionmesh.exe":
            raise IntegrationError("installed_entry_point_invalid")
        windows = self._windows_dir or Path(os.environ.get("SystemRoot", ""))
        wscript = validate_integration_path(windows / "System32" / "wscript.exe", exists=True)
        for enabled, command in ((autostart, "run"), (shortcut, "open")):
            if enabled:
                desired["launchers"][command] = _launcher(
                    self.owner, console, self.data_dir, command
                )
        if autostart:
            desired["task"] = asdict(
                TaskSpec(
                    self.task_name,
                    self.owner,
                    self.sid,
                    str(wscript),
                    subprocess.list2cmdline(
                        ["//B", "//Nologo", str(self.data_dir / "launch-run.vbs")]
                    ),
                )
            )
        if shortcut:
            desired["shortcut"] = asdict(
                ShortcutSpec(
                    str(self.shortcut_path),
                    self.owner,
                    str(wscript),
                    subprocess.list2cmdline(
                        ["//B", "//Nologo", str(self.data_dir / "launch-open.vbs")]
                    ),
                )
            )
        return desired

    def plan(
        self,
        *,
        autostart: bool | None = None,
        shortcut: bool | None = None,
        operation: str = "install",
    ) -> IntegrationPlan:
        if (
            (autostart is not None and type(autostart) is not bool)
            or (shortcut is not None and type(shortcut) is not bool)
            or operation not in {"install", "repair", "remove"}
        ):
            raise IntegrationError("integration_selection_invalid")
        manifest, task, link, launchers = self._observed()
        prior = manifest["pending"] or manifest
        if autostart is None:
            autostart = operation == "repair" and prior["task"] is not None
        if shortcut is None:
            shortcut = operation == "repair" and prior["shortcut"] is not None
        if operation == "remove":
            autostart = shortcut = False
        desired = self._desired(autostart, shortcut)
        observed = {
            "owner": self.owner,
            "task": asdict(task) if task else None,
            "shortcut": asdict(link) if link else None,
            "launchers": launchers,
        }
        changes = tuple(
            key for key in ("task", "shortcut", "launchers") if observed[key] != desired[key]
        )
        snapshot = hashlib.sha256(
            json.dumps([manifest, observed, desired], sort_keys=True).encode()
        ).hexdigest()
        result = IntegrationPlan(
            operation,
            autostart,
            shortcut,
            snapshot,
            changes,
            TaskSpec(**desired["task"]) if desired["task"] else None,
            ShortcutSpec(**desired["shortcut"]) if desired["shortcut"] else None,
            tuple(sorted(desired["launchers"].items())),
        )
        self._plans[snapshot] = result
        # Bounded cache, no authorization conveyed by a reconstructed dataclass.
        if len(self._plans) > 16:
            self._plans.pop(next(iter(self._plans)))
        return result

    def apply(self, plan: IntegrationPlan) -> None:
        if self._plans.get(plan.snapshot) is not plan:
            raise IntegrationError("integration_plan_required")
        # Task identity is per SID, even across data roots and redirected Start
        # Menus. Use the current token's known folder, never LOCALAPPDATA input.
        # Order: caller's data/runtime lock -> integration lock -> metadata locks.
        # Keep the lock file: deleting it permits contenders to lock two inodes.
        lock = validate_integration_path(
            current_user_local_appdata_dir() / "DecisionMesh-Integration"
            / (hashlib.sha256(self.sid.encode()).hexdigest() + ".lock")
        )
        try:
            with owner_file_lock(lock, timeout=0.25):
                self._apply_locked(plan)
        except CaptureError as error:
            code = "integration_busy" if error.code == "capture_busy" else "integration_lock_unavailable"
            raise IntegrationError(code) from None

    def _apply_locked(self, plan: IntegrationPlan) -> None:
        if self._plans.get(plan.snapshot) is not plan:
            raise IntegrationError("integration_plan_required")
        current = self.plan(
            autostart=plan.autostart, shortcut=plan.shortcut, operation=plan.operation
        )
        if current != plan:
            raise IntegrationError("integration_plan_stale")
        self._plans.pop(plan.snapshot, None)
        manifest, task, link, launchers = self._observed()
        desired = {
            "owner": self.owner,
            "task": asdict(plan.task_spec) if plan.task_spec else None,
            "shortcut": asdict(plan.shortcut_spec) if plan.shortcut_spec else None,
            "launchers": dict(plan.launchers),
        }
        ensure_spool_dir(self.data_dir)

        # Journal each successful step. A failure retains exact prior ownership
        # for repair; no wildcard deletion or guessing from display names.
        def record():
            atomic_write_owner_only(
                self.manifest_path, json.dumps(manifest).encode(), max_bytes=MAX_METADATA
            )

        def check_expected():
            # Pending intent proves crash recovery ownership, not permission to
            # replace a newly appeared/different object during this apply.
            _, actual_task, actual_link, actual_launchers = self._observed()
            if (actual_task, actual_link, actual_launchers) != (task, link, launchers):
                raise IntegrationError("foreign_or_modified_entry_preserved")

        try:
            # Promote exactly recognized current objects BEFORE replacing the
            # previous pending intent: it may be their sole crash-surviving
            # ownership evidence. One atomic record retains current + proposed.
            manifest["task"] = asdict(task) if task else None
            manifest["shortcut"] = asdict(link) if link else None
            manifest["launchers"] = dict(launchers)
            manifest["pending"] = desired
            record()
            check_expected()
            for command, body in desired["launchers"].items():
                if launchers.get(command) != body:
                    check_expected()
                    atomic_write_owner_only(
                        self.data_dir / f"launch-{command}.vbs",
                        body.encode("utf-16"),
                        max_bytes=MAX_METADATA,
                        expected_content=(
                            launchers[command].encode("utf-16") if command in launchers else None
                        ),
                    )
                    _, _, _, observed_launchers = self._observed()
                    if observed_launchers.get(command) != body:
                        raise IntegrationError("integration_verification_failed")
                    manifest["launchers"][command] = body
                    launchers[command] = body
                    record()
            if desired["task"] != (asdict(task) if task else None):
                check_expected()
                if desired["task"]:
                    self.backend.write_task(
                        TaskSpec(**desired["task"]), replace=task is not None, expected=task
                    )
                elif task:
                    self.backend.remove_task(self.task_name, expected=task)
                observed_task = self.backend.read_task(self.task_name)
                if (asdict(observed_task) if observed_task else None) != desired["task"]:
                    raise IntegrationError("integration_verification_failed")
                manifest["task"] = desired["task"]
                task = observed_task
                record()
            if desired["shortcut"] != (asdict(link) if link else None):
                check_expected()
                if desired["shortcut"]:
                    self.backend.write_shortcut(ShortcutSpec(**desired["shortcut"]), expected=link)
                elif link:
                    self.backend.remove_shortcut(self.shortcut_path, expected=link)
                observed_link = self.backend.read_shortcut(self.shortcut_path)
                if (asdict(observed_link) if observed_link else None) != desired["shortcut"]:
                    raise IntegrationError("integration_verification_failed")
                manifest["shortcut"] = desired["shortcut"]
                link = observed_link
                record()
            for command in set(launchers) - set(desired["launchers"]):
                path = self.data_dir / f"launch-{command}.vbs"
                check_expected()
                path.unlink()
                if path.exists() or path.is_symlink():
                    raise IntegrationError("integration_verification_failed")
                manifest["launchers"].pop(command, None)
                launchers.pop(command)
                record()
            _, verified_task, verified_link, verified_launchers = self._observed()
            if (
                (asdict(verified_task) if verified_task else None) != desired["task"]
                or (asdict(verified_link) if verified_link else None) != desired["shortcut"]
                or verified_launchers != desired["launchers"]
            ):
                raise IntegrationError("integration_verification_failed")
            # Drop stale absent entries from manifest as well.
            atomic_write_owner_only(
                self.manifest_path,
                json.dumps(desired | {"pending": None}).encode(),
                max_bytes=MAX_METADATA,
            )
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise IntegrationError("integration_apply_incomplete") from None


def proposed_hook_addition(*, capture_executable: Path, spool: Path, policy: Path) -> dict:
    """Review-only exact addition. No file write, trust, host approval or support claim."""
    executable = validate_integration_path(capture_executable, exists=True)
    if executable.name.lower() != "decisionmesh-capture.exe":
        raise IntegrationError("installed_capture_entry_point_invalid")
    command = subprocess.list2cmdline(
        [
            str(executable),
            "--spool",
            str(validate_integration_path(spool)),
            "--policy",
            str(validate_integration_path(policy)),
        ]
    )
    return {"hooks": {"PermissionRequest": [{"hooks": [{"type": "command", "command": command}]}]}}
