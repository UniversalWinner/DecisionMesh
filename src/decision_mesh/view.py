"""Allowlisted public views; private reducer snapshots never cross this boundary."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .contracts import (
    ActionCategory,
    AuthorityReference,
    EvidenceClass,
    GateKind,
    SourceState,
    utc_datetime,
)
from .domain import RequestProjection, VisibilityState
from .presentation.models import (
    STATUS_LABELS,
    DisclosedField,
    NativeChatReference,
    PresentationRecord,
    PresentationStatus,
    RequestType,
)
from .settings import CapturePolicy, Settings
from .storage import StoredRecord


class ViewError(ValueError):
    """Fixed diagnostic code; never includes stored source content."""


def presentation_status(stored: StoredRecord) -> PresentationStatus:
    p = stored.projection
    if p.terminal:
        reported = {
            SourceState.AGENT_RESOLVED: PresentationStatus.AGENT_REPORTED_RESOLVED,
            SourceState.AGENT_WITHDRAWN: PresentationStatus.AGENT_REPORTED_WITHDRAWN,
        }
        return (
            reported[p.source_state]
            if p.source_state in reported
            else PresentationStatus(p.source_state.value)
        )
    if p.source_state == SourceState.PENDING:
        return (
            PresentationStatus.CURRENT_CONFIRMED_PENDING
            if p.current_confirmed
            else PresentationStatus.LAST_KNOWN_PENDING
        )
    if stored.restored:
        return PresentationStatus.RESTORED_UNVERIFIED
    if p.aged or p.visibility == VisibilityState.HISTORY:
        return PresentationStatus.OBSERVATION_AGED
    if p.evidence_class == EvidenceClass.PRODUCER_REPORTED:
        return PresentationStatus.AGENT_REPORTED_QUESTION
    if p.evidence_class == EvidenceClass.PROMPT_CONFIRMED:
        return PresentationStatus.PROMPT_OBSERVED
    return PresentationStatus.GATE_OBSERVED


def _navigation(p: RequestProjection, reference: NativeChatReference | None):
    if reference is None or not reference.navigation_qualified or p.producer_kind != "native":
        return None
    context = p.source_context
    try:
        matches = context is not None and UUID(context.thread_id or "") == reference.thread_id
    except (ValueError, TypeError):
        matches = False
    return reference if matches else None


def to_presentation_record(
    stored: StoredRecord,
    *,
    now: datetime,
    project_alias: str = "Project 1",
    device_alias: str = "This computer",
    allowed_fields: Iterable[DisclosedField | str] = (),
    native_reference: NativeChatReference | None = None,
) -> PresentationRecord:
    """Map only requested fields. Calling code owns authenticated local opt-in.

    There is no reliable request kind after detail pruning, so callers use
    record_view's reference/status fallback instead of manufacturing a question.
    A decision title is not a chat title; host names/paths are never inferred.
    """
    p = stored.projection
    if p.snapshot is None or p.captured_at is None:
        raise ViewError("detail_unavailable")
    if p.last_known_pending and p.last_confirmed_at is None:
        raise ViewError("unconfirmed_pending_missing_time")
    grant = frozenset(DisclosedField(field) for field in allowed_fields)
    values = {
        "action": p.snapshot.action,
        "reason": p.snapshot.reason,
        "scope": p.snapshot.scope,
        "source_reference": p.source_context.thread_id if p.source_context else None,
    }
    details = {key: value for key, value in values.items() if DisclosedField(key) in grant}
    return PresentationRecord(
        record_id=p.record_id,
        short_reference=stored.short_reference,
        request_type=RequestType(p.snapshot.kind.value),
        status=presentation_status(stored),
        captured_at=p.captured_at,
        age_seconds=min(
            3153600000, max(0, int((utc_datetime(now) - p.captured_at).total_seconds()))
        ),
        project_alias=project_alias,
        device_alias=device_alias,
        last_confirmed_at=p.last_confirmed_at,
        native_reference=(
            _navigation(p, native_reference) if DisclosedField.SOURCE_REFERENCE in grant else None
        ),
        **details,
    )


def to_external_record(
    stored: StoredRecord,
    *,
    now: datetime,
    policy: CapturePolicy | None,
    settings: Settings,
    project_alias: str = "Project 1",
) -> PresentationRecord:
    fields = policy.effective_fields(settings) if policy is not None else frozenset()
    return to_presentation_record(
        stored,
        now=now,
        project_alias=project_alias,
        device_alias=settings.device_alias,
        allowed_fields=fields,
    )


@dataclass(frozen=True)
class LocalDetails:
    """Allowlisted data for authenticated local detail pages; render as text."""

    title: str
    summary: str
    task: str | None
    options: tuple[str, ...]
    exclusions: str | None
    gate_kind: GateKind = GateKind.UNCLASSIFIED
    action_category: ActionCategory = ActionCategory.UNKNOWN
    authority_reference: AuthorityReference | None = None
    source_expiry: datetime | None = None


@dataclass(frozen=True)
class RecordView:
    record_id: str
    short_reference: str
    presentation: PresentationRecord | None
    status: PresentationStatus
    evidence_label: str
    captured_at: datetime | None
    aging_deadline: datetime | None
    age_seconds: int | None
    last_confirmed_at: datetime | None
    source_state: str
    evidence_class: str
    execution_state: str
    connection_state: str
    seen: bool
    snoozed_until: datetime | None
    suppressed: bool
    history: bool
    detail_available: bool
    detail_label: str
    needs_attention: bool
    source_confirmed_pending: bool
    status_unverified: bool
    delivery_state: str | None
    local_details: LocalDetails | None = None


def record_view(
    stored: StoredRecord,
    *,
    now: datetime,
    project_alias: str = "Project 1",
    device_alias: str = "This computer",
    allowed_fields: Iterable[DisclosedField | str] = (),
    native_reference: NativeChatReference | None = None,
    delivery_state: str | None = None,
    include_local_details: bool = False,
) -> RecordView:
    if type(include_local_details) is not bool:
        raise ViewError("invalid_local_detail_flag")
    p = stored.projection
    stamp = utc_datetime(now)
    status = presentation_status(stored)
    confirmed = status == PresentationStatus.CURRENT_CONFIRMED_PENDING
    historical = p.terminal or p.visibility == VisibilityState.HISTORY
    snoozed = stored.snoozed_until is not None and stored.snoozed_until > stamp
    unverified = status in {PresentationStatus.LAST_KNOWN_PENDING, PresentationStatus.GATE_OBSERVED}
    available = stored.detail_retained and p.snapshot is not None
    never_confirmed = p.last_known_pending and p.last_confirmed_at is None
    presentation = (
        to_presentation_record(
            stored,
            now=stamp,
            project_alias=project_alias,
            device_alias=device_alias,
            allowed_fields=allowed_fields,
            native_reference=native_reference,
        )
        if available and not never_confirmed
        else None
    )
    return RecordView(
        record_id=p.record_id,
        short_reference=stored.short_reference,
        presentation=presentation,
        status=status,
        evidence_label=(
            "Request details unavailable"
            if p.snapshot is None and p.captured_at is None
            else "Current state has never been confirmed"
            if never_confirmed
            else STATUS_LABELS[status]
        ),
        captured_at=p.captured_at,
        aging_deadline=p.aging_deadline,
        age_seconds=(
            max(0, int((stamp - p.captured_at).total_seconds())) if p.captured_at else None
        ),
        last_confirmed_at=p.last_confirmed_at,
        source_state=p.source_state.value,
        evidence_class=p.evidence_class.value,
        execution_state=p.execution_state.value,
        connection_state=p.connection_state.value,
        seen=stored.seen,
        snoozed_until=stored.snoozed_until,
        suppressed=stored.suppressed,
        history=historical,
        detail_available=available,
        detail_label=(
            "Current state has never been confirmed"
            if never_confirmed
            else "Details available"
            if available
            else "Request details unavailable"
        ),
        needs_attention=(
            available
            and not snoozed
            and not historical
            and (
                confirmed
                or (
                    not stored.seen
                    and status
                    in {
                        PresentationStatus.PROMPT_OBSERVED,
                        PresentationStatus.AGENT_REPORTED_QUESTION,
                    }
                )
            )
        ),
        source_confirmed_pending=confirmed,
        status_unverified=(unverified or p.snapshot is None) and not historical,
        delivery_state=delivery_state,
        local_details=(
            LocalDetails(
                p.snapshot.title,
                p.snapshot.summary,
                p.snapshot.task,
                p.snapshot.options,
                p.snapshot.exclusions,
                gate_kind=p.snapshot.gate_kind,
                action_category=p.snapshot.action_category,
                authority_reference=p.snapshot.authority_reference,
                source_expiry=p.snapshot.source_expiry,
            )
            if include_local_details and available
            else None
        ),
    )
