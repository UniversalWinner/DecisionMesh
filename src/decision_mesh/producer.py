"""Explicit, producer-reported events with durable local revision allocation.

Enrollment is a controlled local setup operation, not an event capability. The
OS account is the trust boundary; this is not protection against that account.
No runtime, host permission, host lifecycle, or delivery is started here.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StrictInt, StringConstraints, field_validator, model_validator

from .capture import (
    CaptureError,
    assert_owner_only,
    atomic_write_owner_only,
    ensure_spool_dir,
    new_capture_metadata,
    owner_file_lock,
    parse_json,
    write_envelope,
)
from .contracts import (
    DecisionSnapshot,
    EventKind,
    EvidenceClass,
    Identifier,
    SourceCapabilities,
    SourceContext,
    StrictModel,
    utc_datetime,
    validate_event,
)

MAX_JOURNAL_BYTES = 1024 * 1024
MAX_RECEIPTS_PER_REQUEST = 1024
EXPLICIT_KINDS = (
    EventKind.REQUEST_OPENED,
    EventKind.REQUEST_UPDATED,
    EventKind.REQUEST_RESOLVED,
    EventKind.REQUEST_WITHDRAWN,
)
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
RevisionNumber = Annotated[StrictInt, Field(ge=1, le=2**63 - 1)]


class ProducerError(RuntimeError):
    """Fixed redacted diagnostic; document and filesystem contents are excluded."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ProducerEnrollment(StrictModel):
    schema_version: Literal[1] = 1
    producer_id: Annotated[str, StringConstraints(pattern=r"^explicit:[0-9a-f]{32}$", strict=True)]

    @property
    def capabilities(self) -> SourceCapabilities:
        return SourceCapabilities(
            producer_id=self.producer_id,
            producer_kind="explicit",
            allowed_event_kinds=EXPLICIT_KINDS,
            allowed_evidence_classes=(EvidenceClass.PRODUCER_REPORTED,),
        )


class ProducerDocument(StrictModel):
    """Complete snapshot; the operation selects its kind and allocates revision."""

    source_request_id: Identifier
    snapshot: DecisionSnapshot
    source_context: SourceContext = SourceContext(producer_kind="explicit")
    occurred_at: datetime | None = None
    idempotency_key: Identifier | None = None

    @field_validator("occurred_at", mode="before")
    @classmethod
    def occurrence_utc(cls, value):
        return None if value is None else utc_datetime(value)

    @model_validator(mode="after")
    def explicit_only(self):
        if self.source_context.producer_kind != "explicit":
            raise ValueError("explicit context required")
        if any(p.asserted_by == "host" for p in self.snapshot.provenance) or (
            self.snapshot.authority_reference is not None
            and self.snapshot.authority_reference.asserted_by == "host"
        ):
            raise ValueError("host provenance is unavailable")
        for value in (self.source_request_id, self.idempotency_key):
            if value is not None and any(ord(char) < 32 for char in value):
                raise ValueError("control characters unavailable")
        return self


class _Allocation(StrictModel):
    event_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$", strict=True)]
    revision: RevisionNumber
    captured_at: datetime
    capture_policy_ref: Identifier | None
    payload_digest: Digest
    key_digest: Digest | None

    @field_validator("captured_at", mode="before")
    @classmethod
    def capture_utc(cls, value):
        return utc_datetime(value)


class _Journal(StrictModel):
    schema_version: Literal[1] = 1
    request_digest: Digest
    max_revision: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)] = 0
    receipts: tuple[_Allocation, ...] = ()

    @model_validator(mode="after")
    def consistent(self):
        revisions = [r.revision for r in self.receipts]
        events = [r.event_id for r in self.receipts]
        keys = [r.key_digest for r in self.receipts if r.key_digest is not None]
        if revisions != sorted(set(revisions)) or len(events) != len(set(events)):
            raise ValueError("allocation identity is inconsistent")
        if len(keys) != len(set(keys)) or self.max_revision != (revisions[-1] if revisions else 0):
            raise ValueError("allocation sequence is inconsistent")
        return self


@dataclass(frozen=True)
class ProducerReceipt:
    producer_id: str
    event_id: str
    source_request_id: str
    revision: int
    captured_at: datetime
    capture_policy_ref: str | None
    idempotency_key: str
    path: Path
    duplicate: bool
    accepted_to_spool: bool = True
    ingested: bool = False


def _digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _read_enrollment(root: Path) -> ProducerEnrollment:
    path = root / "enrollment.json"
    if not path.exists() and not path.is_symlink():
        raise ProducerError("producer_not_enrolled")
    try:
        assert_owner_only(path)
        with path.open("rb") as stream:
            raw = parse_json(stream.read(4097), 4096)
        return ProducerEnrollment.model_validate(raw)
    except FileNotFoundError:
        raise ProducerError("producer_not_enrolled") from None
    except (CaptureError, OSError, ValueError, TypeError):
        raise ProducerError("invalid_enrollment") from None


def enroll_producer(data_dir: Path | str) -> ProducerEnrollment:
    """Idempotent controlled setup. The caller cannot select a foreign namespace.

    The application separately registers ``result.capabilities`` in its store.
    No store is opened, and no envelope can trigger this function.
    """
    try:
        root = ensure_spool_dir(data_dir)
        with owner_file_lock(root / ".enrollment.lock", timeout=5):
            path = root / "enrollment.json"
            if path.exists() or path.is_symlink():
                return _read_enrollment(root)
            enrollment = ProducerEnrollment(producer_id="explicit:" + uuid.uuid4().hex)
            atomic_write_owner_only(path, enrollment.model_dump_json().encode(), max_bytes=4096)
            return enrollment
    except (CaptureError, OSError):
        raise ProducerError("enrollment_unavailable") from None


class ExplicitProducer:
    def __init__(
        self,
        data_dir: Path | str,
        *,
        policy_path: Path | str | None = None,
        clock: Callable[[], datetime] | None = None,
        max_receipts_per_request: int = MAX_RECEIPTS_PER_REQUEST,
        max_journal_bytes: int = MAX_JOURNAL_BYTES,
    ):
        if (
            type(max_receipts_per_request) is not int
            or not 1 <= max_receipts_per_request <= MAX_RECEIPTS_PER_REQUEST
            or type(max_journal_bytes) is not int
            or not 1024 <= max_journal_bytes <= MAX_JOURNAL_BYTES
        ):
            raise ProducerError("invalid_producer_limits")
        try:
            # Reporting requires completed setup; it must not create an
            # unenrolled tree or leave unprotected intermediate directories.
            self.data_dir = Path(data_dir).absolute()
            if not self.data_dir.exists() and not self.data_dir.is_symlink():
                raise ProducerError("producer_not_enrolled")
            assert_owner_only(self.data_dir)
            if not self.data_dir.is_dir():
                raise ProducerError("producer_unavailable")
            self.enrollment = _read_enrollment(self.data_dir)
            self.spool_dir = ensure_spool_dir(self.data_dir / "spool")
            self.journal_dir = ensure_spool_dir(self.data_dir / "journal")
        except (CaptureError, OSError):
            raise ProducerError("producer_unavailable") from None
        self.capabilities = self.enrollment.capabilities
        self.policy_path = policy_path
        self.clock = clock
        self.max_receipts_per_request = max_receipts_per_request
        self.max_journal_bytes = max_journal_bytes

    def create(self, document: ProducerDocument | dict) -> ProducerReceipt:
        return self._publish("request.opened", document)

    def update(self, document: ProducerDocument | dict) -> ProducerReceipt:
        return self._publish("request.updated", document)

    def resolve(self, document: ProducerDocument | dict) -> ProducerReceipt:
        return self._publish("request.resolved", document)

    def withdraw(self, document: ProducerDocument | dict) -> ProducerReceipt:
        return self._publish("request.withdrawn", document)

    def _journal(self, path: Path, request_digest: str) -> _Journal:
        if not path.exists() and not path.is_symlink():
            return _Journal(request_digest=request_digest)
        try:
            assert_owner_only(path)
            with path.open("rb") as stream:
                raw = parse_json(stream.read(self.max_journal_bytes + 1), self.max_journal_bytes)
            journal = _Journal.model_validate(raw)
            if (
                journal.request_digest != request_digest
                or len(journal.receipts) > self.max_receipts_per_request
            ):
                raise ValueError("invalid journal")
            return journal
        except (CaptureError, OSError, ValueError, TypeError):
            raise ProducerError("invalid_allocation_journal") from None

    def _publish(self, kind: str, document: ProducerDocument | dict) -> ProducerReceipt:
        try:
            # Pydantic can trust existing nested model instances even when a
            # mapping is validated. Round-trip both input forms through JSON
            # without input-bearing serializer warnings, then validate every
            # nested field afresh before digesting or allocating anything.
            candidate = (
                document
                if isinstance(document, ProducerDocument)
                else ProducerDocument.model_validate(document)
            )
            document = ProducerDocument.model_validate_json(
                candidate.model_dump_json(warnings=False)
            )
            content = document.model_dump(mode="json", exclude={"idempotency_key"}, warnings=False)
            content["event_kind"] = kind
            body_digest = _digest(
                json.dumps(
                    content,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
            request_digest = _digest(
                self.enrollment.producer_id + "\0" + document.source_request_id
            )
            key_digest = (
                _digest(document.idempotency_key) if document.idempotency_key is not None else None
            )
        except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError):
            raise ProducerError("invalid_producer_document") from None
        path = self.journal_dir / (request_digest + ".json")
        try:
            # Separate from capture's per-target metadata lock: this covers the
            # whole read/allocate/persist/publish transaction for one request.
            with owner_file_lock(self.journal_dir / (request_digest + ".request.lock"), timeout=5):
                journal = self._journal(path, request_digest)
                allocation = None
                if key_digest is not None:
                    allocation = next(
                        (
                            r
                            for r in journal.receipts
                            if r.key_digest == key_digest or _digest(r.event_id) == key_digest
                        ),
                        None,
                    )
                    if allocation is not None and allocation.payload_digest != body_digest:
                        raise ProducerError("idempotency_conflict")
                elif journal.receipts and journal.receipts[-1].payload_digest == body_digest:
                    allocation = journal.receipts[-1]
                duplicate = allocation is not None
                if allocation is None:
                    if (
                        len(journal.receipts) >= self.max_receipts_per_request
                        or journal.max_revision == 2**63 - 1
                    ):
                        raise ProducerError("allocation_capacity")
                    metadata = new_capture_metadata(self.policy_path)
                    if self.clock is not None:
                        metadata["captured_at"] = utc_datetime(self.clock())
                    allocation = _Allocation(
                        **metadata,
                        revision=journal.max_revision + 1,
                        payload_digest=body_digest,
                        key_digest=key_digest,
                    )
                payload = {"snapshot": document.snapshot.model_dump(mode="json", warnings=False)}
                if kind in {"request.resolved", "request.withdrawn"}:
                    payload["outcome"] = "resolved" if kind == "request.resolved" else "withdrawn"
                event = validate_event(
                    {
                        "schema_version": 1,
                        "producer_id": self.enrollment.producer_id,
                        "event_id": allocation.event_id,
                        "event_kind": kind,
                        "source_request_id": document.source_request_id,
                        "revision": allocation.revision,
                        "captured_at": allocation.captured_at.isoformat(),
                        "occurred_at": document.occurred_at.isoformat()
                        if document.occurred_at is not None
                        else None,
                        "capture_policy_ref": allocation.capture_policy_ref,
                        "source_context": document.source_context.model_dump(
                            mode="json", warnings=False
                        ),
                        "evidence_class": "producer_reported",
                        "payload": payload,
                    }
                )
                if not duplicate:
                    updated = _Journal(
                        request_digest=request_digest,
                        max_revision=allocation.revision,
                        receipts=(*journal.receipts, allocation),
                    )
                    encoded = updated.model_dump_json().encode("utf-8")
                    if len(encoded) > self.max_journal_bytes:
                        raise ProducerError("allocation_capacity")
                    # Allocation is durable BEFORE any ready spool file exists.
                    atomic_write_owner_only(path, encoded, max_bytes=self.max_journal_bytes)
                captured = write_envelope(
                    self.spool_dir, event.model_dump(mode="json", warnings=False)
                )
                return ProducerReceipt(
                    producer_id=self.enrollment.producer_id,
                    event_id=allocation.event_id,
                    source_request_id=document.source_request_id,
                    revision=allocation.revision,
                    captured_at=allocation.captured_at,
                    capture_policy_ref=allocation.capture_policy_ref,
                    idempotency_key=allocation.event_id,
                    path=captured.path,
                    duplicate=duplicate,
                )
        except ProducerError:
            raise
        except CaptureError:
            # Allocation remains durable; retry the original document/key.
            raise ProducerError("producer_spool_unavailable") from None
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            raise ProducerError("producer_unavailable") from None
