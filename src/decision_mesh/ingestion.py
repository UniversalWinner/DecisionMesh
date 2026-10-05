"""Source-bound spool import with commit-before-delete and bounded quarantine.

The caller supplies a locally enrolled manifest and sink. No source is enrolled
from event contents. Spool/quarantine are owner-only, unencrypted local data;
malicious processes running as the same OS account are outside this boundary.
"""

from __future__ import annotations

import os
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import Field, StrictInt

from .capture import (
    CaptureError,
    assert_owner_only,
    atomic_write_owner_only,
    ensure_spool_dir,
    owner_file_lock,
    parse_json,
)
from .contracts import (
    MAX_EVENT_BYTES,
    Event,
    SourceCapabilities,
    StrictModel,
    utc_datetime,
    validate_event,
)
from .domain import ResultCategory

MAX_QUARANTINE_BYTES = 16 * 1024 * 1024
_MAX_QUARANTINE_FILES = 1024
_DIAGNOSTIC_RESERVE = 4096
_MAX_DIAGNOSTICS_BYTES = 2048
_MAX_COUNT = 2**63 - 1
DiagnosticCode = Literal[
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
]


class IngestionError(RuntimeError):
    """Only fixed redacted diagnostics leave this boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class CommittedReceipt(Protocol):
    sequence: int
    producer_id: str
    event_id: str
    category: ResultCategory
    replayed: bool


class IngestionSink(Protocol):
    def ingest(
        self,
        raw: bytes | str | dict | Event,
        *,
        received_at: datetime,
        expected_producer_id: str | None = None,
    ) -> CommittedReceipt:
        """Return only after commit; same-event replay returns original identity."""
        ...


class _Diagnostics(StrictModel):
    schema_version: Literal[1] = 1
    counts: dict[DiagnosticCode, Annotated[StrictInt, Field(ge=0, le=_MAX_COUNT)]] = Field(
        default_factory=dict
    )


@dataclass(frozen=True)
class ImportReport:
    scanned: int
    imported: int
    replayed: int
    quarantined: int
    deferred: int
    unsafe: int
    pruned: int
    discarded: int
    diagnostics: dict[str, int]


class SpoolImporter:
    def __init__(
        self,
        spool_dir: Path | str,
        capabilities: SourceCapabilities,
        sink: IngestionSink,
        *,
        quarantine_dir: Path | str | None = None,
        max_quarantine_bytes: int = MAX_QUARANTINE_BYTES,
    ):
        if (
            type(max_quarantine_bytes) is not int
            or not 8192 <= max_quarantine_bytes <= MAX_QUARANTINE_BYTES
        ):
            raise IngestionError("invalid_quarantine_limit")
        try:
            self.capabilities = SourceCapabilities.model_validate_json(
                capabilities.model_dump_json(warnings=False)
            )
            self.spool_dir = ensure_spool_dir(spool_dir)
            self.quarantine_dir = ensure_spool_dir(quarantine_dir or self.spool_dir / ".quarantine")
            # A sibling or child is fine, but ready files and quarantine must
            # never share a directory or import each other's files.
            if (
                self.spool_dir == self.quarantine_dir
                or self.quarantine_dir in self.spool_dir.parents
            ):
                raise IngestionError("invalid_quarantine_path")
        except (CaptureError, OSError, ValueError, TypeError, AttributeError):
            raise IngestionError("source_spool_unavailable") from None
        self.sink = sink
        self.max_quarantine_bytes = max_quarantine_bytes
        self._scan_after: str | None = None
        self._quarantine_inventory: list[tuple[int, str, Path, int]] | None = None

    def _read_diagnostics(self) -> dict[str, int]:
        path = self.quarantine_dir / ".diagnostics.json"
        if not path.exists() and not path.is_symlink():
            return {}
        try:
            assert_owner_only(path)
            with path.open("rb") as stream:
                raw = parse_json(stream.read(_MAX_DIAGNOSTICS_BYTES + 1), _MAX_DIAGNOSTICS_BYTES)
            return dict(_Diagnostics.model_validate(raw).counts)
        except (CaptureError, OSError, ValueError, TypeError):
            raise IngestionError("diagnostics_unavailable") from None

    def _persist(self, cumulative: dict[str, int]) -> None:
        atomic_write_owner_only(
            self.quarantine_dir / ".diagnostics.json",
            _Diagnostics(counts=cumulative).model_dump_json().encode(),
            max_bytes=_MAX_DIAGNOSTICS_BYTES,
        )

    @staticmethod
    def _bump(
        cumulative: dict[str, int], current: dict[str, int], code: DiagnosticCode, amount: int = 1
    ) -> None:
        cumulative[code] = min(_MAX_COUNT, cumulative.get(code, 0) + amount)
        current[code] = min(_MAX_COUNT, current.get(code, 0) + amount)

    @staticmethod
    def _regular_owned(path: Path) -> os.stat_result:
        assert_owner_only(path)
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CaptureError("unsafe_path")
        return info

    @classmethod
    def _unchanged(cls, path: Path, original: os.stat_result) -> None:
        current = cls._regular_owned(path)
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            original.st_dev,
            original.st_ino,
            original.st_size,
            original.st_mtime_ns,
        ):
            raise CaptureError("unsafe_path")

    def _quarantine(
        self,
        path: Path,
        original: os.stat_result,
        cumulative: dict[str, int],
        current: dict[str, int],
    ) -> tuple[int, int]:
        if self._quarantine_inventory is None:
            entries = []
            for entry in self.quarantine_dir.glob("*.bad"):
                info = self._regular_owned(entry)
                entries.append((info.st_mtime_ns, entry.name, entry, info.st_size))
            entries.sort()
            self._quarantine_inventory = entries
        entries = self._quarantine_inventory
        used = sum(item[3] for item in entries)
        budget = self.max_quarantine_bytes - _DIAGNOSTIC_RESERVE
        # Large invalid files are counted then discarded, never copied into
        # quarantine without a bound. Valid-sized rejected bodies are retained
        # locally for inspection when they fit the bounded diagnostic budget.
        discard = original.st_size > MAX_EVENT_BYTES or original.st_size > budget
        incoming = 0 if discard else original.st_size
        pruned = 0
        while entries and (
            used + incoming > budget or len(entries) + int(not discard) > _MAX_QUARANTINE_FILES
        ):
            _, _, entry, size = entries[0]
            self._persist(cumulative)
            entry.unlink()
            entries.pop(0)
            used -= size
            pruned += 1
            self._bump(cumulative, current, "quarantine_pruned")
            self._persist(cumulative)
        self._unchanged(path, original)
        if discard:
            self._persist(cumulative)
            path.unlink()
            self._bump(cumulative, current, "quarantine_discarded")
            self._persist(cumulative)
        else:
            self._persist(cumulative)
            # Source and destination remain on the same filesystem by default.
            # EXDEV or a locked file retains the source and reports deferral.
            target = self.quarantine_dir / (uuid.uuid4().hex + ".bad")
            path.rename(target)
            entries.append((original.st_mtime_ns, target.name, target, original.st_size))
            entries.sort()
        return pruned, int(discard)

    @staticmethod
    def _receipt_valid(receipt: CommittedReceipt, event: Event) -> bool:
        return (
            type(getattr(receipt, "sequence", None)) is int
            and receipt.sequence > 0
            and getattr(receipt, "producer_id", None) == event.producer_id
            and getattr(receipt, "event_id", None) == event.event_id
            and isinstance(getattr(receipt, "category", None), ResultCategory)
            and type(getattr(receipt, "replayed", None)) is bool
        )

    def run_once(self, *, now: datetime, limit: int = 256) -> ImportReport:
        if type(limit) is not int or not 1 <= limit <= 4096:
            raise IngestionError("invalid_import_limit")
        try:
            now = utc_datetime(now)
        except (ValueError, TypeError, OverflowError):
            raise IngestionError("invalid_import_time") from None
        counts = {
            "scanned": 0,
            "imported": 0,
            "replayed": 0,
            "quarantined": 0,
            "deferred": 0,
            "unsafe": 0,
            "pruned": 0,
            "discarded": 0,
        }
        diagnostics: dict[str, int] = {}
        try:
            ensure_spool_dir(self.spool_dir)
            ensure_spool_dir(self.quarantine_dir)
            # A shared quarantine can have more than one source importer.
            with (
                owner_file_lock(self.spool_dir / ".import.lock", timeout=0.25),
                owner_file_lock(self.quarantine_dir / ".quarantine.lock", timeout=0.25),
            ):
                cumulative = self._read_diagnostics()
                self._quarantine_inventory = None
                paths = sorted(
                    p for p in self.spool_dir.glob("*.json") if not p.name.startswith(".")
                )
                remaining = [
                    p for p in paths if self._scan_after is None or p.name > self._scan_after
                ]
                # Move past retained unsafe/deferred files on later batches;
                # one poison prefix must not starve the rest of the source.
                for path in (remaining or paths)[:limit]:
                    self._scan_after = path.name
                    counts["scanned"] += 1
                    try:
                        original = self._regular_owned(path)
                    except (CaptureError, OSError):
                        counts["unsafe"] += 1
                        self._bump(cumulative, diagnostics, "unsafe_entry")
                        continue
                    code: DiagnosticCode | None = None
                    try:
                        if original.st_size > MAX_EVENT_BYTES:
                            code = "event_too_large"
                        else:
                            with path.open("rb") as stream:
                                raw = stream.read(MAX_EVENT_BYTES + 1)
                            self._unchanged(path, original)
                            # Reject duplicate JSON keys, NaN and oversized
                            # input before strict Pydantic schema validation.
                            primitive = parse_json(raw)
                            event = validate_event(primitive, now=now)
                            if event.producer_id != self.capabilities.producer_id:
                                code = "source_namespace_mismatch"
                            elif (
                                event.source_context.producer_kind
                                != self.capabilities.producer_kind
                                or event.event_kind not in self.capabilities.allowed_event_kinds
                                or event.evidence_class
                                not in self.capabilities.allowed_evidence_classes
                            ):
                                code = "source_capability_mismatch"
                    except (
                        CaptureError,
                        ValueError,
                        TypeError,
                        UnicodeError,
                        RecursionError,
                        OverflowError,
                    ):
                        code = "invalid_event"
                    except OSError:
                        counts["deferred"] += 1
                        self._bump(cumulative, diagnostics, "entry_io")
                        continue
                    if code is None:
                        try:
                            receipt = self.sink.ingest(
                                event,
                                received_at=now,
                                expected_producer_id=self.capabilities.producer_id,
                            )
                        except Exception:  # noqa: BLE001 - arbitrary injected sink failures must remain redacted
                            # No sink exception string/body is logged. A
                            # missing/disabled enrollment is also retained
                            # for controlled setup repair, never enrolled.
                            counts["deferred"] += 1
                            self._bump(cumulative, diagnostics, "sink_unavailable")
                            continue
                        if not self._receipt_valid(receipt, event):
                            counts["deferred"] += 1
                            self._bump(cumulative, diagnostics, "sink_receipt_invalid")
                            continue
                        if receipt.category == ResultCategory.CONFLICT:
                            code = "identity_conflict"
                        elif receipt.category == ResultCategory.UNQUALIFIED:
                            code = "source_unqualified"
                        else:
                            # This receipt already survived the sink's
                            # atomic commit. Failure here is safe replay.
                            counts["imported"] += 1
                            counts["replayed"] += int(receipt.replayed)
                            try:
                                self._unchanged(path, original)
                                path.unlink()
                            except (OSError, CaptureError):
                                counts["deferred"] += 1
                                self._bump(cumulative, diagnostics, "delete_deferred")
                            continue
                    self._bump(cumulative, diagnostics, code)
                    try:
                        pruned, discarded = self._quarantine(
                            path, original, cumulative, diagnostics
                        )
                        counts["quarantined"] += 1
                        counts["pruned"] += pruned
                        counts["discarded"] += discarded
                    except (CaptureError, OSError):
                        counts["deferred"] += 1
                        self._bump(cumulative, diagnostics, "quarantine_unavailable")
                self._persist(cumulative)
        except IngestionError:
            raise
        except (CaptureError, OSError):
            raise IngestionError("import_unavailable") from None
        return ImportReport(**counts, diagnostics=diagnostics)
