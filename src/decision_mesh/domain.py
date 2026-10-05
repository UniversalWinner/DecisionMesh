"""Pure replay reducer. Persistence and delivery are deliberately separate layers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from .contracts import (
    ConnectionState,
    DecisionSnapshot,
    Event,
    EventKind,
    EvidenceClass,
    ExecutionEvent,
    ExecutionState,
    HealthEvent,
    RequestEvent,
    SourceCapabilities,
    SourceContext,
    SourceState,
    TerminalEvent,
    canonical_request_id,
    event_digest,
    snapshot_digest,
    utc_datetime,
)


class VisibilityState(StrEnum):
    ACTIVE = "active"
    HISTORY = "history"


class ResultCategory(StrEnum):
    APPLY = "apply"
    DUPLICATE = "duplicate"
    STALE = "stale"
    CONFLICT = "conflict"
    UNQUALIFIED = "unqualified"


TERMINAL_STATES = frozenset(set(SourceState) - {SourceState.PENDING, SourceState.UNVERIFIED})
RequestKey = tuple[str, str]
RecordKey = RequestKey | tuple[str, str, str]


@dataclass(frozen=True)
class RequestProjection:
    key: RecordKey
    record_id: str
    producer_kind: str
    source_request_id: str | None
    request_revision: int = 0
    execution_revision: int = 0
    snapshot: DecisionSnapshot | None = None
    snapshot_digest: str | None = None
    source_context: SourceContext | None = None
    source_state: SourceState = SourceState.UNVERIFIED
    evidence_class: EvidenceClass = EvidenceClass.GATE_OBSERVED
    visibility: VisibilityState = VisibilityState.ACTIVE
    execution_state: ExecutionState = ExecutionState.NOT_OBSERVED
    execution_id: str | None = None
    connection_state: ConnectionState = ConnectionState.UNKNOWN
    current_confirmed: bool = False
    last_confirmed_at: datetime | None = None
    captured_at: datetime | None = None
    aging_deadline: datetime | None = None
    aged: bool = False
    opening_observed: bool = False
    capture_policy_ref: str | None = None
    limitations: tuple[str, ...] = ()

    @property
    def terminal(self) -> bool:
        return self.source_state in TERMINAL_STATES

    @property
    def last_known_pending(self) -> bool:
        return self.source_state == SourceState.PENDING and not self.current_confirmed


@dataclass(frozen=True)
class EventReceipt:
    key: tuple[str, str]
    digest: str
    received_at: datetime


@dataclass(frozen=True)
class RevisionReceipt:
    key: RequestKey
    stream: str
    revision: int
    digest: str


@dataclass(frozen=True)
class SourceHealth:
    producer_id: str
    connection_state: ConnectionState
    captured_at: datetime
    recovery_barrier_at: datetime | None = None


@dataclass(frozen=True)
class SessionEnd:
    """Compact qualified end evidence; retained independently of detailed records."""

    producer_id: str
    scope: tuple[tuple[str, str], ...]
    ended_at: datetime


@dataclass(frozen=True)
class AuditEntry:
    event: Event
    digest: str
    received_at: datetime
    category: ResultCategory
    flags: tuple[str, ...]


@dataclass(frozen=True)
class MeshState:
    records: tuple[RequestProjection, ...] = ()
    events: tuple[EventReceipt, ...] = ()
    revisions: tuple[RevisionReceipt, ...] = ()
    sources: tuple[SourceHealth, ...] = ()
    session_ends: tuple[SessionEnd, ...] = ()
    audit: tuple[AuditEntry, ...] = ()

    def record(self, key: RecordKey) -> RequestProjection | None:
        return next((record for record in self.records if record.key == key), None)


@dataclass(frozen=True)
class ReductionResult:
    category: ResultCategory
    state: MeshState
    record: RequestProjection | None
    flags: tuple[str, ...] = ()


def _put_record(state: MeshState, record: RequestProjection) -> MeshState:
    others = tuple(r for r in state.records if r.key != record.key)
    return replace(state, records=tuple(sorted((*others, record), key=lambda r: r.key)))


def _source(state: MeshState, producer_id: str) -> SourceHealth | None:
    return next((s for s in state.sources if s.producer_id == producer_id), None)


def _recovery_barrier(state: MeshState, producer_id: str) -> datetime | None:
    health = _source(state, producer_id)
    if health is None:
        return None
    # Older persisted health values remain conservative when the new field is absent.
    return health.recovery_barrier_at or (
        health.captured_at if health.connection_state != ConnectionState.CONTINUOUS else None
    )


def _put_health(state: MeshState, health: SourceHealth) -> MeshState:
    previous = _source(state, health.producer_id)
    barriers = [
        stamp
        for stamp in (_recovery_barrier(state, health.producer_id), health.recovery_barrier_at)
        if stamp is not None
    ]
    barrier = max(barriers) if barriers else None
    if previous is not None:
        health = replace(
            health,
            captured_at=max(previous.captured_at, health.captured_at),
            connection_state=(
                previous.connection_state
                if previous.captured_at > health.captured_at
                else health.connection_state
            ),
            recovery_barrier_at=barrier,
        )
    else:
        health = replace(health, recovery_barrier_at=barrier)
    others = tuple(s for s in state.sources if s.producer_id != health.producer_id)
    return replace(state, sources=tuple(sorted((*others, health), key=lambda s: s.producer_id)))


def _connection(state: MeshState, producer_id: str) -> ConnectionState:
    source = _source(state, producer_id)
    return source.connection_state if source else ConnectionState.UNKNOWN


def _session_end_scope(context: SourceContext, capabilities: SourceCapabilities):
    # A thread is not proof of a particular session/turn ending.
    if context.session_id is None and context.turn_id is None:
        return None
    required = set(capabilities.identity_scope) - {"native_request_id"}
    if any(getattr(context, name) is None for name in required):
        return None
    names = ("thread_id", "session_id", "turn_id", "source_instance_id")
    return tuple(
        sorted(
            (name, getattr(context, name)) for name in names if getattr(context, name) is not None
        )
    )


def _put_session_end(state: MeshState, end: SessionEnd) -> MeshState:
    previous = next(
        (
            item
            for item in state.session_ends
            if item.producer_id == end.producer_id and item.scope == end.scope
        ),
        None,
    )
    if previous is not None:
        end = replace(end, ended_at=max(previous.ended_at, end.ended_at))
    others = tuple(
        item
        for item in state.session_ends
        if (item.producer_id, item.scope) != (end.producer_id, end.scope)
    )
    return replace(
        state,
        session_ends=tuple(sorted((*others, end), key=lambda item: (item.producer_id, item.scope))),
    )


def _end_covers(end: SessionEnd, context: SourceContext, captured_at: datetime) -> bool:
    if captured_at > end.ended_at:
        return False
    scope = dict(end.scope)
    if any(getattr(context, name) != value for name, value in scope.items()):
        return False
    # Missing known scope cannot merge instances, threads or sessions. A session end
    # intentionally covers all its turns; a turn end compares its exact turn above.
    return not any(
        name not in scope and getattr(context, name) is not None
        for name in ("thread_id", "session_id", "source_instance_id")
    )


def _ended_at_capture(
    state: MeshState, producer_id: str, context: SourceContext, captured_at: datetime
) -> bool:
    return any(
        end.producer_id == producer_id and _end_covers(end, context, captured_at)
        for end in state.session_ends
    )


def _revision_digest(event: Event) -> str:
    """New transport IDs/stamps do not make identical source revisions substantive."""
    data = {
        "event_kind": event.event_kind,
        "evidence_class": event.evidence_class.value,
        "source_context": event.source_context.model_dump(
            mode="json", exclude={"connection_epoch"}
        ),
        "payload": event.payload.model_dump(mode="json"),
    }
    body = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _native_identity(event: Event, capabilities: SourceCapabilities) -> bool:
    reference = getattr(event.payload, "native_reference", None)
    if reference is None:
        snapshot = getattr(event.payload, "snapshot", None)
        reference = snapshot.native_reference if snapshot else None
    if reference is None:
        return False
    try:
        if canonical_request_id(reference, capabilities.identity_scope) != event.source_request_id:
            return False
    except (ValueError, AttributeError):
        return False
    # Duplicated context must agree; omitted context remains honest null, not inferred.
    for name in ("thread_id", "session_id", "source_instance_id"):
        context_value = getattr(event.source_context, name)
        reference_value = getattr(reference, name)
        if context_value is not None and context_value != reference_value:
            return False
    return True


def _qualification(event: Event, capabilities: SourceCapabilities) -> str | None:
    if event.producer_id != capabilities.producer_id:
        return "producer_namespace_mismatch"
    if event.source_context.producer_kind != capabilities.producer_kind:
        return "producer_kind_mismatch"
    if EventKind(event.event_kind) not in capabilities.allowed_event_kinds:
        return "event_kind_not_qualified"
    if event.evidence_class not in capabilities.allowed_evidence_classes:
        return "evidence_class_not_qualified"
    if isinstance(event, (RequestEvent, TerminalEvent, ExecutionEvent)):
        if capabilities.producer_kind == "native":
            if event.evidence_class != EvidenceClass.SOURCE_AUTHORITATIVE:
                return "native_lifecycle_not_qualified_use_observation"
            if not capabilities.authoritative_lifecycle or not _native_identity(
                event, capabilities
            ):
                return "native_identity_not_qualified_use_observation"
        elif isinstance(event, ExecutionEvent):
            return "execution_not_qualified"
    if isinstance(event, TerminalEvent):
        if event.event_kind == "request.corrected" and capabilities.producer_kind != "native":
            return "correction_requires_qualified_source"
        if capabilities.producer_kind == "native" and event.payload.outcome == "resolved":
            return "native_closure_requires_exact_outcome_or_closed_unknown"
    if isinstance(event, HealthEvent) and (
        capabilities.producer_kind != "native"
        or event.evidence_class != EvidenceClass.SOURCE_AUTHORITATIVE
    ):
        return "health_requires_qualified_source"
    return None


def disconnect_source(
    state: MeshState,
    producer_id: str,
    *,
    now: datetime,
    connection: ConnectionState = ConnectionState.DISCONNECTED,
) -> MeshState:
    """Restart/gap/disconnection demotes confirmation, never claims source closure."""
    stamp = utc_datetime(now)
    state = _put_health(state, SourceHealth(producer_id, connection, stamp, stamp))
    for record in state.records:
        if record.key[0] == producer_id:
            state = _put_record(
                state, replace(record, current_confirmed=False, connection_state=connection)
            )
    return state


def _replay_health_loss(
    state: MeshState,
    producer_id: str,
    *,
    captured_at: datetime,
    connection: ConnectionState,
) -> MeshState:
    """Apply ordered health evidence without undoing later per-request qualification."""
    prior_barrier = _recovery_barrier(state, producer_id)
    state = _put_health(state, SourceHealth(producer_id, connection, captured_at, captured_at))
    loss_connection = (
        _connection(state, producer_id)
        if prior_barrier is not None and captured_at < prior_barrier
        else connection
    )
    barrier = _recovery_barrier(state, producer_id)
    for record in state.records:
        if record.key[0] != producer_id:
            continue
        covered = (
            record.current_confirmed
            and record.last_confirmed_at is not None
            and barrier is not None
            and record.last_confirmed_at > barrier
        )
        if not covered:
            state = _put_record(
                state, replace(record, current_confirmed=False, connection_state=loss_connection)
            )
    return state


def age_state(state: MeshState, *, now: datetime) -> MeshState:
    stamp = utc_datetime(now)
    for record in state.records:
        if (
            record.aging_deadline is not None
            and not record.aged
            and not record.terminal
            and stamp >= record.aging_deadline
        ):
            state = _put_record(
                state, replace(record, aged=True, visibility=VisibilityState.HISTORY)
            )
    return state


def reduce_event(
    state: MeshState,
    event: Event,
    *,
    received_at: datetime,
    capabilities: SourceCapabilities,
) -> ReductionResult:
    stamp = utc_datetime(received_at)
    digest = event_digest(event)
    event_key = (event.producer_id, event.event_id)
    key = (
        (event.producer_id, event.source_request_id)
        if event.source_request_id is not None
        else (event.producer_id, "", event.event_id)
    )
    record = state.record(key)

    def finish(category, flags=(), *, projected=None, remember=True):
        nonlocal state
        if projected is not None:
            state = _put_record(state, projected)
        if remember:
            state = replace(state, events=(*state.events, EventReceipt(event_key, digest, stamp)))
        state = replace(
            state, audit=(*state.audit, AuditEntry(event, digest, stamp, category, flags))
        )
        return ReductionResult(category, state, projected or state.record(key), flags)

    receipt = next((r for r in state.events if r.key == event_key), None)
    if receipt is not None:
        category = ResultCategory.DUPLICATE if receipt.digest == digest else ResultCategory.CONFLICT
        return finish(
            category,
            ("event_replay" if category == ResultCategory.DUPLICATE else "event_payload_conflict",),
            remember=False,
        )
    capture_age = stamp - event.captured_at
    if capture_age > timedelta(days=30):
        return finish(ResultCategory.UNQUALIFIED, ("capture_outside_acceptance_window",))
    if capture_age < -timedelta(minutes=5):
        return finish(ResultCategory.UNQUALIFIED, ("capture_in_future",))
    failure = _qualification(event, capabilities)
    if failure:
        return finish(ResultCategory.UNQUALIFIED, (failure,))

    if isinstance(event, HealthEvent):
        health = event.payload
        if health.connection_state != ConnectionState.CONTINUOUS:
            state = _replay_health_loss(
                state,
                event.producer_id,
                captured_at=event.captured_at,
                connection=health.connection_state,
            )
        else:
            previous = _source(state, event.producer_id)
            connection = (
                previous.connection_state
                if previous is not None
                and previous.connection_state
                in {ConnectionState.GAPPED, ConnectionState.DISCONNECTED}
                else ConnectionState.CONTINUOUS
            )
            state = _put_health(
                state, SourceHealth(event.producer_id, connection, event.captured_at)
            )
        # Source health alone cannot reconcile exact request identities.
        flags = []
        if health.session_ended and capabilities.authoritative_lifecycle:
            scope = _session_end_scope(event.source_context, capabilities)
            if scope is None:
                flags.append("session_end_scope_unqualified")
            else:
                state = _put_session_end(
                    state, SessionEnd(event.producer_id, scope, event.captured_at)
                )
                for item in state.records:
                    if (
                        item.key[0] == event.producer_id
                        and item.aging_deadline is not None
                        and not item.terminal
                        and item.source_context is not None
                        and item.captured_at is not None
                        and _ended_at_capture(
                            state, item.key[0], item.source_context, item.captured_at
                        )
                    ):
                        state = _put_record(
                            state, replace(item, aged=True, visibility=VisibilityState.HISTORY)
                        )
        return finish(ResultCategory.APPLY, tuple(flags))

    stream = "execution" if isinstance(event, ExecutionEvent) else "request"
    revision = event.revision
    if revision is not None:
        revision_digest = _revision_digest(event)
        prior = next(
            (
                r
                for r in state.revisions
                if r.key == key and r.stream == stream and r.revision == revision
            ),
            None,
        )
        if prior:
            category = (
                ResultCategory.DUPLICATE
                if prior.digest == revision_digest
                else ResultCategory.CONFLICT
            )
            return finish(
                category,
                (
                    "revision_replay"
                    if category == ResultCategory.DUPLICATE
                    else "revision_payload_conflict",
                ),
            )
        state = replace(
            state,
            revisions=(*state.revisions, RevisionReceipt(key, stream, revision, revision_digest)),
        )
        previous_revision = (
            (record.execution_revision if stream == "execution" else record.request_revision)
            if record
            else 0
        )
        if revision < previous_revision:
            return finish(ResultCategory.STALE, ("lower_revision",))
    else:
        previous_revision = 0

    flags = []
    orphan = previous_revision == 0 and event.event_kind not in {
        "request.opened",
        "observation.recorded",
    }
    if orphan:
        flags.append("opening_not_observed")
    prior_barrier = _recovery_barrier(state, event.producer_id)
    gap = revision is not None and revision > previous_revision + 1
    if gap:
        flags.append("revision_gap")
        if capabilities.producer_kind == "native":
            state = disconnect_source(
                state, event.producer_id, now=event.captured_at, connection=ConnectionState.GAPPED
            )
            record = state.record(key)
    if record is None:
        record = RequestProjection(
            key=key,
            record_id="dm-" + hashlib.sha256(json.dumps(key).encode()).hexdigest()[:20],
            producer_kind=capabilities.producer_kind,
            source_request_id=event.source_request_id,
            source_context=event.source_context,
            evidence_class=event.evidence_class,
            captured_at=event.captured_at,
            capture_policy_ref=event.capture_policy_ref,
            connection_state=_connection(state, event.producer_id),
        )

    if isinstance(event, ExecutionEvent):
        if not capabilities.one_to_one_execution or event.payload.mapping != "one_to_one":
            limitations = tuple(
                dict.fromkeys((*record.limitations, "execution_mapping_unqualified"))
            )
            return finish(
                ResultCategory.UNQUALIFIED,
                (*flags, "execution_mapping_unqualified"),
                projected=replace(record, limitations=limitations),
            )
        if record.execution_id is not None and record.execution_id != event.payload.execution_id:
            return finish(ResultCategory.CONFLICT, ("execution_identity_changed",))
        if (
            record.execution_state in {ExecutionState.SUCCEEDED, ExecutionState.FAILED}
            and event.payload.execution_state != record.execution_state
        ):
            return finish(ResultCategory.CONFLICT, ("execution_terminal_no_resurrection",))
        return finish(
            ResultCategory.APPLY,
            tuple(flags),
            projected=replace(
                record,
                execution_revision=revision,
                execution_id=event.payload.execution_id,
                execution_state=ExecutionState(event.payload.execution_state),
            ),
        )

    if isinstance(event, TerminalEvent):
        if event.event_kind == "request.corrected":
            if orphan or not record.terminal or record.producer_kind != "native":
                return finish(
                    ResultCategory.UNQUALIFIED, ("correction_requires_attested_terminal",)
                )
        elif record.terminal and event.payload.outcome != record.source_state.value:
            # Explicit reported resolution differs in vocabulary from source outcomes.
            same_report = (
                record.source_state == SourceState.AGENT_RESOLVED
                and event.payload.outcome == "resolved"
            ) or (
                record.source_state == SourceState.AGENT_WITHDRAWN
                and event.payload.outcome == "withdrawn"
            )
            if not same_report:
                return finish(ResultCategory.CONFLICT, ("outcome_change_requires_correction",))
        outcome = event.payload.outcome
        source_state = (
            (SourceState.AGENT_WITHDRAWN if outcome == "withdrawn" else SourceState.AGENT_RESOLVED)
            if capabilities.producer_kind == "explicit"
            else SourceState(outcome)
        )
        projected = replace(
            record,
            request_revision=revision,
            snapshot=event.payload.snapshot,
            snapshot_digest=snapshot_digest(event.payload.snapshot),
            source_context=event.source_context,
            source_state=source_state,
            evidence_class=event.evidence_class,
            visibility=VisibilityState.HISTORY,
            current_confirmed=False,
            captured_at=event.captured_at,
            capture_policy_ref=event.capture_policy_ref,
            aging_deadline=None,
            opening_observed=record.opening_observed,
        )
        return finish(ResultCategory.APPLY, tuple(flags), projected=projected)

    if record.terminal:
        return finish(ResultCategory.CONFLICT, ("terminal_no_resurrection",))
    payload = event.payload
    authoritative = event.evidence_class == EvidenceClass.SOURCE_AUTHORITATIVE
    confirmed = False
    connection = record.connection_state
    if authoritative:
        barrier = _recovery_barrier(state, event.producer_id)
        recovery_fresh = barrier is None or event.captured_at > barrier
        # A qualified current snapshot may cover a gap revealed by THIS revision.
        # It never covers a previously known barrier at the same or later time.
        if (
            gap
            and barrier == event.captured_at
            and (prior_barrier is None or event.captured_at > prior_barrier)
        ):
            recovery_fresh = True
        if (
            payload.authoritative_current
            and payload.continuity_restored
            and capabilities.authoritative_current_snapshots
        ):
            if recovery_fresh:
                connection = ConnectionState.CONTINUOUS
                confirmed = True
            else:
                flags.append("reconciliation_predates_recovery_barrier")
        elif (
            capabilities.continuous_stream
            and connection == ConnectionState.CONTINUOUS
            and not orphan
            and not gap
            and recovery_fresh
        ):
            confirmed = True
    if orphan and not confirmed and connection == ConnectionState.CONTINUOUS:
        # Merely collecting an orphan update must not establish the missing
        # request-stream continuity for a later ordinary update.
        connection = ConnectionState.UNKNOWN
    incoming_snapshot_digest = snapshot_digest(payload.snapshot)
    previous_snapshot_digest = record.snapshot_digest or (
        snapshot_digest(record.snapshot) if record.snapshot is not None else None
    )
    substantive = (
        previous_snapshot_digest != incoming_snapshot_digest
        or record.evidence_class != event.evidence_class
    )
    if not substantive:
        flags.append("non_substantive_revision")
    captured = event.captured_at if substantive else record.captured_at
    deadline = None if authoritative else captured + timedelta(minutes=60)
    ended = deadline is not None and _ended_at_capture(
        state, event.producer_id, event.source_context, captured
    )
    if ended:
        flags.append("source_session_ended")
    aged = deadline is not None and (
        ended or stamp >= deadline or (record.aged and not substantive)
    )
    projected = replace(
        record,
        request_revision=revision or record.request_revision,
        snapshot=payload.snapshot,
        snapshot_digest=incoming_snapshot_digest,
        source_context=event.source_context,
        source_state=SourceState.PENDING if authoritative else SourceState.UNVERIFIED,
        evidence_class=event.evidence_class,
        current_confirmed=confirmed,
        last_confirmed_at=(
            max(event.captured_at, record.last_confirmed_at)
            if confirmed and record.last_confirmed_at is not None
            else event.captured_at
            if confirmed
            else record.last_confirmed_at
        ),
        connection_state=connection,
        captured_at=captured,
        aging_deadline=deadline,
        aged=aged,
        visibility=VisibilityState.HISTORY if aged else VisibilityState.ACTIVE,
        opening_observed=record.opening_observed or event.event_kind == "request.opened",
        capture_policy_ref=event.capture_policy_ref if substantive else record.capture_policy_ref,
    )
    return finish(ResultCategory.APPLY, tuple(flags), projected=projected)
