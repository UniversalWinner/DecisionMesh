"""Redacted local diagnostics: no payloads, credentials or rendezvous fields."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .capture import assert_owner_only, atomic_write_owner_only, parse_json
from .runtime_control import (
    RuntimeErrorCode,
    RuntimePaths,
    active_metadata,
    authenticate,
    resolve_installed_console,
)
from .storage import SQLiteStore

CODES = frozenset(
    {"setup_unavailable", "policy_publication_failed", "scan_failed", "delivery_failed"}
)
INGEST_CODES = frozenset(
    {
        "invalid_event",
        "event_too_large",
        "source_namespace_mismatch",
        "source_capability_mismatch",
        "identity_conflict",
        "source_unqualified",
        "unsafe_entry",
        "entry_io",
        "sink_unavailable",
        "sink_receipt_invalid",
        "delete_deferred",
        "quarantine_unavailable",
        "quarantine_pruned",
        "quarantine_discarded",
    }
)
CAPTURE_CODES = frozenset(
    {
        "capture_busy",
        "unsafe_path",
        "invalid_json",
        "invalid_envelope",
        "event_too_large",
        "event_conflict",
        "spool_capacity",
        "spool_io",
        "local_file_io",
        "owner_acl_invalid",
        "owner_acl_unavailable",
        "local_partial_capacity",
        "local_file_too_large",
        "owner_sid_mismatch",
    }
)


def _owned_json(path, limit=8192):
    assert_owner_only(path)
    with path.open("rb") as stream:
        return parse_json(stream.read(limit + 1), limit)


def _counts(path, allowlist):
    if not path.exists():
        return {"status": "absent", "counts": {}}
    try:
        raw = _owned_json(path).get("counts", {})
        if not isinstance(raw, dict):
            raise TypeError()
        counts = {
            code: value
            for code, value in raw.items()
            if code in allowlist and type(value) is int and 0 <= value <= 2**63 - 1
        }
        return {"status": "available", "counts": counts}
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        return {"status": "failed", "counts": {}}


class RuntimeCounters:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.counts = _counts(self.path, CODES)["counts"]
        self.persistence_failed = False

    def bump(self, code):
        if code not in CODES:
            raise ValueError("invalid_diagnostic_code")
        with self.lock:
            self.counts[code] = min(2**63 - 1, self.counts.get(code, 0) + 1)
            try:
                atomic_write_owner_only(
                    self.path,
                    json.dumps({"schema_version": 1, "counts": self.counts}).encode(),
                    max_bytes=8192,
                )
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                self.persistence_failed = True


def _inventory(directory, suffix):
    if not directory.exists():
        return {"status": "absent", "files": 0, "bytes": 0, "bounded": False}
    try:
        assert_owner_only(directory)
        count = total = 0
        for scanned, item in enumerate(directory.iterdir()):
            if scanned >= 4096:
                return {"status": "available", "files": count, "bytes": total, "bounded": True}
            if item.name.startswith(".") or item.suffix != suffix:
                continue
            if count >= 4096:
                return {"status": "available", "files": count, "bytes": total, "bounded": True}
            assert_owner_only(item)
            count += 1
            total += item.stat().st_size
        return {"status": "available", "files": count, "bytes": total, "bounded": False}
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        return {"status": "failed", "files": None, "bytes": None, "bounded": False}


def doctor(paths: RuntimePaths, *, probe=authenticate):
    report = {
        "schema_version": 1,
        "runtime": "absent",
        "storage": {"status": "absent"},
        "native_support": "unverified",
        "hook_trust": "unverified",
        "secret_backend": "not_checked",
        "setup": "absent",
        "verification_scope": "local_runtime",
        "environment_verified": False,
        "local_capture_verified": False,
        "last_provider_acceptance": None,
        "delivery_check": "absent",
        "sources": {"status": "absent", "total": 0, "entries": [], "more": False},
        "provider_acceptance_meaning": "API acceptance does not prove delivery or reading",
    }
    try:
        metadata = active_metadata(paths)
        if metadata is not None:
            probe(metadata, "open")
            report["runtime"] = "authenticated_ready"
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        report["runtime"] = "authentication_or_metadata_failed"
    if paths.database.exists():
        try:
            summary = SQLiteStore.inspect_summary(paths.database, verify_integrity=True)
            report["storage"] = {
                "status": "available",
                "schema_version": summary.schema_version,
                "integrity_ok": summary.integrity_ok,
                "source_count": summary.source_count,
                "enabled_source_count": summary.enabled_source_count,
                "qualified_native_source_count": summary.qualified_native_source_count,
                "last_capture_at": summary.last_capture_at.isoformat()
                if summary.last_capture_at
                else None,
                "diagnostic_count": summary.diagnostic_count,
                "diagnostic_counts": summary.diagnostic_counts,
            }
        except Exception:  # noqa: BLE001 - storage errors remain independent of optional checks
            report["storage"] = {"status": "failed"}
        try:
            sources = SQLiteStore.inspect_source_page(paths.database, limit=50)
            report["sources"] = {
                "status": "available",
                "total": sources.total,
                "more": sources.next_cursor is not None,
                "entries": [
                    {
                        "kind": row.capabilities.producer_kind,
                        "enabled": row.enabled,
                        "qualified": row.qualified,
                        "authoritative_lifecycle": row.capabilities.authoritative_lifecycle,
                        "authoritative_current_snapshots": row.capabilities.authoritative_current_snapshots,
                        "continuous_stream": row.capabilities.continuous_stream,
                        "connection_state": row.health.connection_state.value
                        if row.health
                        else "unobserved",
                    }
                    for row in sources.sources
                ],
            }
        except Exception:  # noqa: BLE001 - no partial source details on failure
            report["sources"] = {"status": "failed", "total": None, "entries": [], "more": False}
        try:
            from .delivery import DeliveryWorker

            delivery = DeliveryWorker.inspect_summary(paths.database)
            report["delivery_check"] = "available"
            report["last_provider_acceptance"] = (
                delivery.last_api_acceptance_at.isoformat()
                if delivery.last_api_acceptance_at
                else None
            )
        except Exception:  # noqa: BLE001 - provider history failure is not a storage-health result
            report["delivery_check"] = "failed"
    setup_path = paths.root / "setup.json"
    if setup_path.exists():
        try:
            from .setup import SetupState

            setup = SetupState.model_validate(_owned_json(setup_path))
            report["setup"] = setup.stage
            report["secret_backend"] = (
                "unavailable_at_last_check"
                if setup.stage == "credentials_unavailable"
                else "not_checked_now"
            )
            report["local_capture_verified"] = setup.local_capture_verified
            report["environment_verified"] = setup.environment_signature is not None
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            report["setup"] = "failed"
    try:
        installed = resolve_installed_console()
    except RuntimeErrorCode:
        installed = None
    report["installed_command"] = (
        "available" if installed and Path(installed).is_file() else "missing_or_stale"
    )
    manifest = paths.root / "windows-integration.json"
    report["windows_integration"] = "not_configured"
    if manifest.exists():
        try:
            saved = _owned_json(manifest, 32768)
            launchers = saved.get("launchers", {})
            report["windows_integration"] = (
                "installed_paths_unverified" if launchers else "not_configured"
            )
            for name, script in launchers.items():
                if name not in {"run", "open"} or not isinstance(script, str):
                    raise ValueError("invalid_integration_manifest")
                path = paths.root / ("launch-" + name + ".vbs")
                assert_owner_only(path)
                with path.open("rb") as stream:
                    actual = stream.read(32769)
                if (
                    len(actual) > 32768
                    or actual.decode("utf-16") != script
                    or not installed
                    or str(Path(installed)).casefold() not in script.casefold()
                ):
                    report["windows_integration"] = "stale_installed_paths"
            for key in ("task", "shortcut"):
                item = saved.get(key)
                if item and (
                    not isinstance(item, dict) or not Path(item.get("command", "")).is_file()
                ):
                    report["windows_integration"] = "stale_installed_paths"
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            report["windows_integration"] = "manifest_failed"
    spool = paths.producer / "spool"
    report["spool"] = _inventory(spool, ".json")
    report["quarantine"] = _inventory(spool / ".quarantine", ".bad")
    report["runtime_counters"] = _counts(paths.root / "runtime-diagnostics.json", CODES)
    report["capture_counters"] = {"status": "absent", "lost_count_lower_bound": None}
    marker = spool / ".capture-failure"
    if marker.exists():
        try:
            failure = _owned_json(marker, 1024)
            code, count = failure.get("code"), failure.get("lost_count_lower_bound")
            if code not in CAPTURE_CODES or type(count) is not int or count < 1:
                raise ValueError("invalid_capture_marker")
            report["capture_counters"] = {
                "status": "available",
                "code": code,
                "lost_count_lower_bound": count,
            }
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            report["capture_counters"] = {"status": "failed", "lost_count_lower_bound": None}
    report["import_counters"] = _counts(spool / ".quarantine" / ".diagnostics.json", INGEST_CODES)
    return report


def export_report(report, destination):
    target = Path(destination)
    if not target.is_absolute() or target.exists() or target.is_symlink():
        raise ValueError("new_absolute_export_path_required")
    # Only doctor()'s fixed report is an export input; callers must not add payloads.
    atomic_write_owner_only(target, json.dumps(report, sort_keys=True).encode(), max_bytes=32768)
