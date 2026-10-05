"""Version-one allowlisted event contracts. No payload grants permission."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

MAX_EVENT_BYTES = 256 * 1024
Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
Title = Annotated[str, StringConstraints(strict=True, max_length=160)]
Summary = Annotated[str, StringConstraints(strict=True, max_length=2048)]
Reason = Annotated[str, StringConstraints(strict=True, max_length=4096)]
Revision = Annotated[StrictInt, Field(gt=0, le=2**63 - 1)]


class EventKind(StrEnum):
    OBSERVATION_RECORDED = "observation.recorded"
    REQUEST_OPENED = "request.opened"
    REQUEST_UPDATED = "request.updated"
    REQUEST_RESOLVED = "request.resolved"
    REQUEST_WITHDRAWN = "request.withdrawn"
    REQUEST_CORRECTED = "request.corrected"
    EXECUTION_UPDATED = "execution.updated"
    SOURCE_HEALTH = "source.health"


class EvidenceClass(StrEnum):
    GATE_OBSERVED = "gate_observed"
    PROMPT_CONFIRMED = "prompt_confirmed"
    SOURCE_AUTHORITATIVE = "source_authoritative"
    PRODUCER_REPORTED = "producer_reported"


class GateKind(StrEnum):
    USER_AUTHORITY = "user_authority"
    TECHNICAL_REVIEW = "technical_review"
    PLATFORM_PERMISSION = "platform_permission"
    RUNTIME_ADMISSION = "runtime_admission"
    UNCLASSIFIED = "unclassified"


class DecisionKind(StrEnum):
    PERMISSION = "permission"
    QUESTION = "question"
    CHOICE = "choice"


class ActionCategory(StrEnum):
    TESTING = "testing"
    IMPLEMENTATION = "implementation"
    DOWNLOAD = "download"
    INSTALLATION = "installation"
    GENERAL = "general"
    UNKNOWN = "unknown"


class SourceState(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    ANSWERED = "answered"
    DECLINED = "declined"
    CANCELLED = "cancelled"
    CLOSED_UNKNOWN = "closed_unknown"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    REPLACED = "replaced"
    AGENT_RESOLVED = "agent_resolved"
    AGENT_WITHDRAWN = "agent_withdrawn"


class ExecutionState(StrEnum):
    NOT_OBSERVED = "not_observed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ConnectionState(StrEnum):
    UNKNOWN = "unknown"
    CONTINUOUS = "continuous"
    DISCONNECTED = "disconnected"
    GAPPED = "gapped"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


def utc_datetime(value: object) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO8601") from exc
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone aware")
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise ValueError("timestamp cannot be represented in UTC") from exc


class SourceContext(StrictModel):
    producer_kind: Literal["native", "explicit"]
    host: Identifier | None = None
    surface: Identifier | None = None
    version: Identifier | None = None
    thread_id: Identifier | None = None
    turn_id: Identifier | None = None
    session_id: Identifier | None = None
    source_instance_id: Identifier | None = None
    connection_epoch: Identifier | None = None


class NativeReference(StrictModel):
    native_request_id: Identifier
    thread_id: Identifier | None = None
    session_id: Identifier | None = None
    source_instance_id: Identifier | None = None


class Provenance(StrictModel):
    field: Literal[
        "kind",
        "gate_kind",
        "action_category",
        "title",
        "summary",
        "task",
        "action",
        "scope",
        "exclusions",
        "reason",
        "options",
        "source_expiry",
        "native_reference",
        "authority_reference",
    ]
    asserted_by: Literal["host", "agent", "user"]
    source_pointer: Summary | None = None


class AuthorityReference(StrictModel):
    source_pointer: Summary | None = None
    quote: Reason | None = None
    scope: Summary | None = None
    exclusions: Summary | None = None
    supplied_lifetime: Summary | None = None
    asserted_by: Literal["host", "agent", "user"]

    @model_validator(mode="after")
    def has_reference(self):
        if self.source_pointer is None and self.quote is None:
            raise ValueError("authority reference needs a pointer or quote")
        return self


class DecisionSnapshot(StrictModel):
    kind: DecisionKind
    gate_kind: GateKind = GateKind.UNCLASSIFIED
    action_category: ActionCategory = ActionCategory.UNKNOWN
    title: Title = ""
    summary: Summary = ""
    task: Summary | None = None
    action: Summary | None = None
    scope: Summary | None = None
    exclusions: Summary | None = None
    reason: Reason | None = None
    options: Annotated[tuple[Title, ...], Field(max_length=32)] = ()
    source_expiry: datetime | None = None
    native_reference: NativeReference | None = None
    provenance: Annotated[tuple[Provenance, ...], Field(max_length=16)] = ()
    authority_reference: AuthorityReference | None = None

    @field_validator("source_expiry", mode="before")
    @classmethod
    def expiry_utc(cls, value):
        return None if value is None else utc_datetime(value)

    @model_validator(mode="after")
    def unique_provenance(self):
        names = [p.field for p in self.provenance]
        if len(names) != len(set(names)):
            raise ValueError("duplicate field provenance")
        return self


class SnapshotPayload(StrictModel):
    snapshot: DecisionSnapshot
    authoritative_current: StrictBool = False
    continuity_restored: StrictBool = False


TerminalOutcome = Literal[
    "answered",
    "declined",
    "cancelled",
    "closed_unknown",
    "expired",
    "withdrawn",
    "replaced",
    "resolved",
]


class TerminalPayload(SnapshotPayload):
    outcome: TerminalOutcome
    replacement_request_id: Identifier | None = None

    @model_validator(mode="after")
    def replacement_evidence(self):
        if self.outcome == "replaced" and self.replacement_request_id is None:
            raise ValueError("replacement needs exact source identity")
        return self


class ExecutionPayload(StrictModel):
    execution_id: Identifier
    execution_state: Literal["running", "succeeded", "failed"]
    mapping: Literal["one_to_one", "grouped", "unknown"]
    native_reference: NativeReference | None = None


class HealthPayload(StrictModel):
    connection_state: ConnectionState
    reconciled: StrictBool = False
    session_ended: StrictBool = False


class EnvelopeBase(StrictModel):
    schema_version: Literal[1]
    producer_id: Identifier
    event_id: Identifier
    captured_at: datetime
    occurred_at: datetime | None = None
    source_context: SourceContext
    evidence_class: EvidenceClass
    capture_policy_ref: Identifier | None = None

    @field_validator("schema_version", mode="before")
    @classmethod
    def version_integer(cls, value):
        if type(value) is not int:
            raise ValueError("schema version must be integer 1")
        return value

    @field_validator("captured_at", "occurred_at", mode="before")
    @classmethod
    def timestamp_utc(cls, value):
        return None if value is None else utc_datetime(value)

    @model_validator(mode="after")
    def explicit_evidence(self):
        if self.source_context.producer_kind == "explicit":
            if self.evidence_class != EvidenceClass.PRODUCER_REPORTED:
                raise ValueError("explicit producer cannot attest host evidence")
            snapshot = getattr(self.payload, "snapshot", None)
            if snapshot is not None and (
                any(p.asserted_by == "host" for p in snapshot.provenance)
                or (
                    snapshot.authority_reference is not None
                    and snapshot.authority_reference.asserted_by == "host"
                )
            ):
                raise ValueError("explicit producer cannot assert host provenance")
            if getattr(self.payload, "authoritative_current", False) or getattr(
                self.payload, "continuity_restored", False
            ):
                raise ValueError("explicit producer cannot assert current-source continuity")
            if isinstance(self.payload, TerminalPayload) and self.payload.outcome not in {
                "resolved",
                "withdrawn",
            }:
                raise ValueError("explicit terminals must be reported resolved or withdrawn")
        return self


class ObservationEvent(EnvelopeBase):
    event_kind: Literal["observation.recorded"]
    source_request_id: None = None
    revision: None = None
    payload: SnapshotPayload

    @model_validator(mode="after")
    def observation_evidence(self):
        if self.evidence_class == EvidenceClass.SOURCE_AUTHORITATIVE:
            raise ValueError("uncorrelated observation cannot assert lifecycle authority")
        return self


class RequestEvent(EnvelopeBase):
    event_kind: Literal["request.opened", "request.updated"]
    source_request_id: Identifier
    revision: Revision
    payload: SnapshotPayload


class TerminalEvent(EnvelopeBase):
    event_kind: Literal["request.resolved", "request.withdrawn", "request.corrected"]
    source_request_id: Identifier
    revision: Revision
    payload: TerminalPayload

    @model_validator(mode="after")
    def terminal_semantics(self):
        if self.event_kind == "request.withdrawn" and self.payload.outcome != "withdrawn":
            raise ValueError("withdrawal must report withdrawn")
        if self.event_kind == "request.resolved" and self.payload.outcome == "withdrawn":
            raise ValueError("withdrawal uses request.withdrawn")
        return self


class ExecutionEvent(EnvelopeBase):
    event_kind: Literal["execution.updated"]
    source_request_id: Identifier
    revision: Revision
    payload: ExecutionPayload


class HealthEvent(EnvelopeBase):
    event_kind: Literal["source.health"]
    source_request_id: None = None
    revision: None = None
    payload: HealthPayload


EventEnvelope = Annotated[
    ObservationEvent | RequestEvent | TerminalEvent | ExecutionEvent | HealthEvent,
    Field(discriminator="event_kind"),
]
Event = ObservationEvent | RequestEvent | TerminalEvent | ExecutionEvent | HealthEvent
EVENT_ADAPTER = TypeAdapter(EventEnvelope)


class SourceCapabilities(StrictModel):
    producer_id: Identifier
    producer_kind: Literal["native", "explicit"]
    allowed_event_kinds: tuple[EventKind, ...]
    allowed_evidence_classes: tuple[EvidenceClass, ...]
    identity_scope: tuple[
        Literal["native_request_id", "thread_id", "session_id", "source_instance_id"], ...
    ] = ()
    authoritative_lifecycle: StrictBool = False
    authoritative_current_snapshots: StrictBool = False
    continuous_stream: StrictBool = False
    one_to_one_execution: StrictBool = False

    @model_validator(mode="after")
    def trust_boundary(self):
        if len(set(self.identity_scope)) != len(self.identity_scope):
            raise ValueError("identity scope must not repeat components")
        if self.producer_kind == "explicit" and (
            any(e != EvidenceClass.PRODUCER_REPORTED for e in self.allowed_evidence_classes)
            or self.authoritative_lifecycle
            or self.authoritative_current_snapshots
            or self.continuous_stream
            or self.one_to_one_execution
        ):
            raise ValueError("explicit capabilities cannot assert source authority")
        if (
            self.producer_kind == "native"
            and self.authoritative_lifecycle
            and "native_request_id" not in self.identity_scope
        ):
            raise ValueError("native lifecycle needs documented identity scope")
        return self


def canonical_request_id(reference: NativeReference, identity_scope: tuple[str, ...]) -> str:
    """Adapter ID from documented scope only; never include reconnect epoch or text."""
    if "native_request_id" not in identity_scope or len(set(identity_scope)) != len(identity_scope):
        raise ValueError("documented native identity scope required")
    values = {name: getattr(reference, name) for name in identity_scope}
    if any(value is None for value in values.values()):
        raise ValueError("all documented native identity components required")
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "native:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_event_bytes(event: Event) -> bytes:
    return _canonical_json_bytes(event.model_dump(mode="json"))


def event_digest(event: Event) -> str:
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()


def snapshot_digest(snapshot: DecisionSnapshot) -> str:
    """Internal compact identity for substantive evidence after detail pruning."""
    return hashlib.sha256(_canonical_json_bytes(snapshot.model_dump(mode="json"))).hexdigest()


def validate_event(raw: bytes | str | dict, *, now: datetime | None = None) -> Event:
    """Validate bounded data; callers log only error locations/codes, never raw bodies."""
    if isinstance(raw, dict):
        encoded = json.dumps(
            raw,
            ensure_ascii=False,
            default=lambda v: v.isoformat() if isinstance(v, datetime) else v,
            allow_nan=False,
        ).encode("utf-8")
    elif isinstance(raw, str):
        encoded = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise TypeError("event input must be JSON bytes, string or object")
    if len(encoded) > MAX_EVENT_BYTES:
        raise ValueError("event exceeds 256 KiB")
    event = EVENT_ADAPTER.validate_json(encoded)
    if now is not None:
        current = utc_datetime(now)
        capture_age = current - event.captured_at
        if capture_age > timedelta(days=30):
            raise ValueError("capture is outside the 30-day acceptance window")
        if capture_age < -timedelta(minutes=5):
            raise ValueError("capture is more than five minutes in the future")
    return event


def event_schema() -> dict:
    return EVENT_ADAPTER.json_schema()
