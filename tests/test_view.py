"""Public privacy/status mapping, independent of source authority and sending."""

from dataclasses import asdict, replace
from datetime import timedelta
from uuid import UUID

import pytest

from decision_mesh.contracts import (
    ConnectionState,
    DecisionSnapshot,
    EvidenceClass,
    ExecutionState,
    SourceContext,
    SourceState,
)
from decision_mesh.domain import RequestProjection, VisibilityState
from decision_mesh.presentation.models import NativeChatReference, PresentationStatus
from decision_mesh.settings import CapturePolicy, DestinationIdentity, Settings
from decision_mesh.storage import StoredRecord
from decision_mesh.view import ViewError, record_view, to_external_record, to_presentation_record


@pytest.fixture
def record(now):
    projection = RequestProjection(
        key=("agent-local", "q1"),
        record_id="record-1",
        producer_kind="explicit",
        source_request_id="q1",
        request_revision=1,
        snapshot=DecisionSnapshot(
            kind="question",
            title="PRIVATE DECISION TITLE",
            summary="PRIVATE SUMMARY",
            action="PRIVATE ACTION",
            reason="PRIVATE REASON",
            scope="PRIVATE SCOPE",
            authority_reference={"asserted_by": "agent", "quote": "PRIVATE AUTHORITY"},
        ),
        snapshot_digest="PRIVATE DIGEST",
        captured_at=now,
        aging_deadline=now + timedelta(hours=1),
        source_context=SourceContext(
            producer_kind="explicit", host="PRIVATE HOST", thread_id="PRIVATE THREAD"
        ),
        evidence_class=EvidenceClass.PRODUCER_REPORTED,
    )
    return StoredRecord(projection, "ABCDEFGH", True, False, None, False, False)


def altered(record, **changes):
    return replace(record, projection=replace(record.projection, **changes))


def test_minimal_defaults_no_source_context_private_digest_or_evidence_leak(record, now):
    view = record_view(record, now=now)
    assert "PRIVATE" not in repr(asdict(view))
    assert view.presentation.project_alias == "Project 1"
    assert view.presentation.device_alias == "This computer"
    assert view.presentation.native_reference is None
    assert view.evidence_label == "Agent-reported question (not verified)"
    assert view.needs_attention and not view.source_confirmed_pending


def test_allowlisted_local_details_are_explicit_and_not_chat_title(record, now):
    view = record_view(
        record,
        now=now,
        allowed_fields=(
            "action",
            "reason",
            "scope",
            "chat_title",
            "source_path",
            "source_reference",
        ),
    )
    assert view.presentation.action == "PRIVATE ACTION"
    assert view.presentation.reason == "PRIVATE REASON"
    assert view.presentation.scope == "PRIVATE SCOPE"
    assert view.presentation.source_reference == "PRIVATE THREAD"
    assert view.presentation.chat_title is None and view.presentation.source_path is None
    assert "PRIVATE AUTHORITY" not in repr(asdict(view))
    assert "PRIVATE DIGEST" not in repr(asdict(view))


def test_external_capture_current_intersection_and_generation(record, now):
    destination = DestinationIdentity(chat_id=1, bot_id=2)
    policy = CapturePolicy(
        policy_ref="p",
        settings_revision=0,
        destination_generation=1,
        channel_active=True,
        destination=destination,
        disclosure_fields={"action", "reason"},
        created_at=now,
    )
    settings = Settings(
        destination=destination,
        destination_generation=1,
        channel_active=True,
        disclosure_fields={"action", "scope"},
    )
    public = to_external_record(record, now=now, policy=policy, settings=settings)
    assert public.action == "PRIVATE ACTION"
    assert public.scope is None and public.reason is None
    revoked = settings.model_copy(update={"destination_generation": 2})
    assert "PRIVATE" not in repr(
        to_external_record(record, now=now, policy=policy, settings=revoked).model_dump()
    )


@pytest.mark.parametrize(
    "source,label",
    [
        (SourceState.ANSWERED, "Answered"),
        (SourceState.DECLINED, "Declined"),
        (SourceState.CANCELLED, "Cancelled"),
        (SourceState.CLOSED_UNKNOWN, "Closed; answer unknown"),
        (SourceState.EXPIRED, "Expired"),
        (SourceState.WITHDRAWN, "Withdrawn"),
        (SourceState.REPLACED, "Replaced"),
        (SourceState.AGENT_RESOLVED, "Agent reported: resolved"),
        (SourceState.AGENT_WITHDRAWN, "Agent reported: withdrawn"),
    ],
)
def test_exact_terminal_precedence_and_independent_execution(record, now, source, label):
    stored = altered(
        record, source_state=source, aged=True, execution_state=ExecutionState.NOT_OBSERVED
    )
    public = record_view(stored, now=now)
    assert public.evidence_label == label
    assert public.history and not public.needs_attention
    assert public.execution_state == "not_observed"


def test_last_known_has_confirmation_and_remains_unverified(record, now):
    stored = altered(
        record,
        producer_kind="native",
        source_state=SourceState.PENDING,
        evidence_class=EvidenceClass.SOURCE_AUTHORITATIVE,
        current_confirmed=False,
        last_confirmed_at=now - timedelta(minutes=5),
        connection_state=ConnectionState.DISCONNECTED,
    )
    public = record_view(replace(stored, restored=True), now=now)
    assert public.evidence_label == "Last known pending; current state unverified"
    assert public.presentation.last_confirmed_at == now - timedelta(minutes=5)
    assert public.status_unverified and not public.history and not public.needs_attention
    assert public.connection_state == "disconnected"


def test_confirmed_seen_stays_attention_but_snoozed_only_confirmed_filter(record, now):
    stored = altered(
        record,
        source_state=SourceState.PENDING,
        current_confirmed=True,
        last_confirmed_at=now,
        evidence_class=EvidenceClass.SOURCE_AUTHORITATIVE,
    )
    seen = replace(stored, seen=True)
    assert record_view(seen, now=now).needs_attention
    snoozed = record_view(replace(seen, snoozed_until=now + timedelta(minutes=10)), now=now)
    assert not snoozed.needs_attention and snoozed.source_confirmed_pending
    assert snoozed.evidence_label == "Waiting for you (confirmed by Codex)"


def test_seen_suppression_gate_and_history_independent(record, now):
    assert not record_view(replace(record, seen=True), now=now).needs_attention
    assert record_view(replace(record, suppressed=True), now=now).needs_attention
    gate = record_view(altered(record, evidence_class=EvidenceClass.GATE_OBSERVED), now=now)
    assert gate.status_unverified and not gate.needs_attention
    assert gate.evidence_label == "Gate observed; no prompt confirmed"
    prompt = record_view(altered(record, evidence_class=EvidenceClass.PROMPT_CONFIRMED), now=now)
    assert prompt.evidence_label == "Prompt observed; may already be answered"
    historical = record_view(
        altered(record, aged=True, visibility=VisibilityState.HISTORY), now=now + timedelta(hours=2)
    )
    assert historical.history and not historical.needs_attention
    assert historical.evidence_label == "Observation aged; current state unverified"
    assert historical.age_seconds == 7200
    assert historical.captured_at == now


def test_pruned_reference_fallback_no_invented_kind_and_live_orphan_not_history(record, now):
    stored = replace(
        altered(record, snapshot=None, aged=True, visibility=VisibilityState.HISTORY),
        detail_retained=False,
    )
    view = record_view(stored, now=now)
    assert view.presentation is None and view.short_reference == "ABCDEFGH"
    assert view.detail_label == "Request details unavailable"
    assert view.history and view.aging_deadline == now + timedelta(hours=1)
    assert "PRIVATE DIGEST" not in repr(asdict(view))
    with pytest.raises(ViewError, match="detail_unavailable"):
        to_presentation_record(stored, now=now)
    orphan = replace(altered(record, snapshot=None, captured_at=None), detail_retained=False)
    assert record_view(orphan, now=now).presentation is None
    assert not record_view(orphan, now=now).history
    assert not record_view(orphan, now=now).needs_attention
    assert record_view(orphan, now=now).status_unverified
    assert record_view(orphan, now=now).evidence_label == "Request details unavailable"


def test_native_navigation_requires_qualified_structured_matching_uuid(record, now):
    thread = UUID("11111111-2222-3333-4444-555555555555")
    stored = altered(
        record,
        producer_kind="native",
        source_context=SourceContext(producer_kind="native", thread_id=str(thread)),
    )
    assert (
        to_presentation_record(
            stored, now=now, allowed_fields=("source_reference",)
        ).native_reference
        is None
    )
    ref = NativeChatReference(thread_id=thread, navigation_qualified=True)
    assert (
        to_presentation_record(
            stored, now=now, allowed_fields=("source_reference",), native_reference=ref
        ).native_reference
        == ref
    )
    assert to_presentation_record(stored, now=now, native_reference=ref).native_reference is None
    assert (
        to_presentation_record(
            record, now=now, allowed_fields=("source_reference",), native_reference=ref
        ).native_reference
        is None
    )
    invalid = altered(
        stored,
        source_context=SourceContext(producer_kind="native", thread_id="https://evil.invalid/path"),
    )
    assert (
        to_presentation_record(
            invalid, now=now, allowed_fields=("source_reference",), native_reference=ref
        ).native_reference
        is None
    )


def test_future_capture_age_zero_no_status_upgrade(record, now):
    view = record_view(record, now=now - timedelta(minutes=3), delivery_state="accepted")
    assert view.age_seconds == 0
    assert view.delivery_state == "accepted"
    assert view.status == PresentationStatus.AGENT_REPORTED_QUESTION


def test_native_pending_never_confirmed_has_no_invented_confirmation_time(record, now):
    stored = altered(
        record,
        source_state=SourceState.PENDING,
        current_confirmed=False,
        last_confirmed_at=None,
        evidence_class=EvidenceClass.SOURCE_AUTHORITATIVE,
    )
    view = record_view(stored, now=now)
    assert view.presentation is None and view.last_confirmed_at is None
    assert view.detail_available and view.status_unverified
    assert view.detail_label == "Current state has never been confirmed"
    assert view.evidence_label == "Current state has never been confirmed"
    with pytest.raises(ViewError, match="unconfirmed_pending_missing_time"):
        to_presentation_record(stored, now=now)


def test_local_question_details_opt_in_never_enter_external_projection(record, now):
    payload = '<script>alert("untrusted")</script>'
    stored = altered(
        record,
        snapshot=record.projection.snapshot.model_copy(
            update={
                "title": payload,
                "summary": "Question summary",
                "task": "Reported task",
                "options": ("A", "B"),
                "exclusions": "Does not authorize execution",
            }
        ),
    )
    assert record_view(stored, now=now).local_details is None
    local = record_view(stored, now=now, include_local_details=True)
    assert local.local_details.title == payload  # plain data; UI must escape it
    assert local.local_details.summary == "Question summary"
    assert local.local_details.options == ("A", "B")
    assert local.local_details.exclusions == "Does not authorize execution"
    assert local.presentation.chat_title is None and local.presentation.action is None
    assert local.local_details.authority_reference.quote == "PRIVATE AUTHORITY"
    external = to_external_record(stored, now=now, policy=None, settings=Settings())
    assert payload not in repr(external.model_dump())
    assert "Question summary" not in repr(external.model_dump())
    assert "PRIVATE AUTHORITY" not in repr(external.model_dump())
    assert "local_details" not in type(external).model_fields
    pruned = replace(altered(stored, snapshot=None), detail_retained=False)
    assert record_view(pruned, now=now, include_local_details=True).local_details is None
