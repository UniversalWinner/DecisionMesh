import json
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from itertools import permutations
from pathlib import Path

import pytest

from decision_mesh.contracts import ConnectionState, ExecutionState, SourceState, validate_event
from decision_mesh.domain import (
    MeshState,
    VisibilityState,
    age_state,
    disconnect_source,
    reduce_event,
)
from decision_mesh.domain import (
    ResultCategory as C,
)


def apply(state, event, now, capabilities):
    return reduce_event(state, event, received_at=now, capabilities=capabilities)


def test_duplicate_same_id_and_payload_conflict_keep_original(
    event_factory, now, explicit_capabilities
):
    event = event_factory()
    initial = apply(MeshState(), event, now, explicit_capabilities)
    replay = apply(initial.state, event, now + timedelta(minutes=70), explicit_capabilities)
    assert replay.category == C.DUPLICATE
    assert replay.record == initial.record
    assert len(replay.state.events) == 1
    altered = event_factory(snapshot_changes={"title": "Different"})
    conflict = apply(replay.state, altered, now, explicit_capabilities)
    assert conflict.category == C.CONFLICT
    assert conflict.record.snapshot.title == "Choose a test target"
    assert len(conflict.state.events) == 1
    assert conflict.state.audit[-1].event.payload.snapshot.title == "Different"


def test_two_same_looking_requests_never_merge(event_factory, now, explicit_capabilities):
    first = event_factory(request_id="request-A", event_id="A")
    second = event_factory(request_id="request-B", event_id="B")
    state = apply(MeshState(), first, now, explicit_capabilities).state
    result = apply(state, second, now, explicit_capabilities)
    assert result.category == C.APPLY
    assert len(result.state.records) == 2
    assert len({r.record_id for r in result.state.records}) == 2


def test_revision_replays_conflicts_stale_and_gap(event_factory, now, explicit_capabilities):
    opening = event_factory()
    state = apply(MeshState(), opening, now, explicit_capabilities).state
    replay = event_factory(event_id="new-transport-id", captured_at=now + timedelta(minutes=1))
    result = apply(state, replay, now + timedelta(minutes=1), explicit_capabilities)
    assert result.category == C.DUPLICATE
    assert result.record.captured_at == now
    conflict = event_factory(event_id="bad-revision", snapshot_changes={"summary": "changed"})
    assert apply(result.state, conflict, now, explicit_capabilities).category == C.CONFLICT
    gap = event_factory(event_kind="request.updated", revision=4)
    result = apply(result.state, gap, now, explicit_capabilities)
    assert result.category == C.APPLY and "revision_gap" in result.flags
    lower = event_factory(event_kind="request.updated", revision=2)
    stale = apply(result.state, lower, now, explicit_capabilities)
    assert stale.category == C.STALE
    assert stale.record.request_revision == 4


@pytest.mark.parametrize(
    "kind,outcome,state",
    [
        ("request.updated", None, SourceState.UNVERIFIED),
        ("request.resolved", "resolved", SourceState.AGENT_RESOLVED),
        ("request.withdrawn", "withdrawn", SourceState.AGENT_WITHDRAWN),
    ],
)
def test_orphan_full_snapshots_project_reported_state(
    event_factory, now, explicit_capabilities, kind, outcome, state
):
    event = event_factory(event_kind=kind, revision=3, outcome=outcome)
    result = apply(MeshState(), event, now, explicit_capabilities)
    assert result.category == C.APPLY
    assert result.record.source_state == state
    assert "opening_not_observed" in result.flags
    assert result.record.opening_observed is False


def test_orphan_native_pending_needs_current_authoritative_snapshot(
    event_factory, now, native_capabilities
):
    orphan = event_factory(event_kind="request.updated", native=True, revision=2)
    first = apply(MeshState(), orphan, now, native_capabilities)
    assert first.record.source_state == SourceState.PENDING
    assert first.record.last_known_pending and not first.record.current_confirmed
    snapshot = event_factory(
        event_kind="request.updated",
        native=True,
        revision=3,
        current=True,
        restored=True,
        captured_at=now + timedelta(minutes=1),
    )
    reconciled = apply(first.state, snapshot, now + timedelta(minutes=1), native_capabilities)
    assert reconciled.record.current_confirmed
    assert reconciled.record.last_confirmed_at == now + timedelta(minutes=1)
    next_event = event_factory(
        event_kind="request.updated",
        native=True,
        revision=4,
        captured_at=now + timedelta(minutes=2),
    )
    assert apply(
        reconciled.state, next_event, now + timedelta(minutes=2), native_capabilities
    ).record.current_confirmed


def test_terminal_no_resurrection_and_agent_report_label(event_factory, now, explicit_capabilities):
    opened = event_factory()
    result = apply(MeshState(), opened, now, explicit_capabilities)
    terminal = event_factory(event_kind="request.resolved", revision=2, outcome="resolved")
    result = apply(result.state, terminal, now, explicit_capabilities)
    assert result.record.source_state == SourceState.AGENT_RESOLVED
    assert result.record.visibility == VisibilityState.HISTORY
    assert not result.record.current_confirmed
    replay = apply(result.state, opened, now, explicit_capabilities)
    assert replay.category == C.DUPLICATE and replay.record.terminal
    reopened = event_factory(event_kind="request.updated", revision=3)
    conflict = apply(replay.state, reopened, now, explicit_capabilities)
    assert conflict.category == C.CONFLICT and conflict.record.terminal


def test_lower_unseen_revision_after_terminal_is_stale(event_factory, now, explicit_capabilities):
    terminal = event_factory(event_kind="request.resolved", revision=5, outcome="resolved")
    result = apply(MeshState(), terminal, now, explicit_capabilities)
    result = apply(result.state, event_factory(revision=1), now, explicit_capabilities)
    assert result.category == C.STALE
    assert result.record.terminal


def test_native_closure_unknown_is_not_answered_and_correction_preserves_evidence(
    event_factory, now, native_capabilities
):
    closed = event_factory(native=True, event_kind="request.resolved", outcome="closed_unknown")
    result = apply(MeshState(), closed, now, native_capabilities)
    assert result.record.source_state == SourceState.CLOSED_UNKNOWN
    bad = event_factory(native=True, event_kind="request.resolved", revision=2, outcome="answered")
    conflict = apply(result.state, bad, now, native_capabilities)
    assert conflict.category == C.CONFLICT
    corrected = event_factory(
        native=True, event_kind="request.corrected", revision=3, outcome="answered"
    )
    result = apply(conflict.state, corrected, now, native_capabilities)
    assert result.category == C.APPLY
    assert result.record.source_state == SourceState.ANSWERED
    assert result.state.audit[0].event.payload.outcome == "closed_unknown"
    assert result.record.execution_state == ExecutionState.NOT_OBSERVED
    assert result.record.snapshot.authority_reference is None


def test_orphan_and_producer_corrections_are_unqualified(
    event_factory, now, native_capabilities, explicit_capabilities
):
    orphan = event_factory(native=True, event_kind="request.corrected", outcome="answered")
    result = apply(MeshState(), orphan, now, native_capabilities)
    assert result.category == C.UNQUALIFIED and result.record is None
    reported = event_factory(event_kind="request.corrected", outcome="resolved")
    assert apply(MeshState(), reported, now, explicit_capabilities).category == C.UNQUALIFIED


def test_disconnect_gap_reconciliation_and_pending_never_ages(
    event_factory, now, native_capabilities
):
    first = event_factory(native=True, current=True, restored=True)
    result = apply(MeshState(), first, now, native_capabilities)
    assert result.record.current_confirmed
    disconnected = disconnect_source(result.state, first.producer_id, now=now)
    record = disconnected.record(result.record.key)
    assert record.last_known_pending and record.last_confirmed_at == now
    assert record.connection_state == ConnectionState.DISCONNECTED
    health = event_factory(
        native=True,
        event_kind="source.health",
        event_id="connected",
        payload_changes={"reconciled": True},
    )
    connected = apply(disconnected, health, now, native_capabilities)
    assert not connected.state.record(record.key).current_confirmed
    gap = event_factory(native=True, event_kind="request.updated", revision=3)
    result = apply(connected.state, gap, now, native_capabilities)
    assert "revision_gap" in result.flags and not result.record.current_confirmed
    assert result.record.connection_state == ConnectionState.GAPPED
    aged = age_state(result.state, now=now + timedelta(days=3))
    assert aged.record(record.key).visibility == VisibilityState.ACTIVE
    assert aged.record(record.key).aging_deadline is None
    restore = event_factory(
        native=True,
        event_kind="request.updated",
        revision=4,
        current=True,
        restored=True,
        captured_at=now + timedelta(minutes=1),
    )
    assert apply(
        aged, restore, now + timedelta(minutes=1), native_capabilities
    ).record.current_confirmed


def test_source_reconciliation_does_not_confirm_other_requests(
    event_factory, now, native_capabilities
):
    a = event_factory(native=True, request_id="A", event_id="A1", current=True, restored=True)
    b = event_factory(native=True, request_id="B", event_id="B1", current=True, restored=True)
    state = apply(MeshState(), a, now, native_capabilities).state
    state = apply(state, b, now, native_capabilities).state
    state = disconnect_source(state, "codex-native", now=now)
    a2 = event_factory(
        native=True,
        request_id="A",
        event_id="A2",
        revision=2,
        event_kind="request.updated",
        current=True,
        restored=True,
        captured_at=now + timedelta(minutes=1),
    )
    result = apply(state, a2, now + timedelta(minutes=1), native_capabilities)
    assert result.record.current_confirmed
    assert result.state.record(("codex-native", b.source_request_id)).last_known_pending


def test_old_spool_age_at_ingest_and_duplicate_does_not_refresh(
    event_factory, now, explicit_capabilities
):
    event = event_factory(captured_at=now - timedelta(minutes=61))
    result = apply(MeshState(), event, now, explicit_capabilities)
    assert result.record.aged and result.record.visibility == VisibilityState.HISTORY
    assert result.record.aging_deadline == now - timedelta(minutes=1)
    back = age_state(result.state, now=now - timedelta(hours=5))
    assert back.record(result.record.key).aged
    replay = apply(back, event, now, explicit_capabilities)
    assert replay.category == C.DUPLICATE and replay.record.aged
    update = event_factory(
        event_kind="request.updated",
        revision=2,
        captured_at=now,
        snapshot_changes={"summary": "New substantive question"},
    )
    refreshed = apply(replay.state, update, now, explicit_capabilities)
    assert not refreshed.record.aged
    assert refreshed.record.aging_deadline == now + timedelta(minutes=60)
    assert refreshed.record.source_state == SourceState.UNVERIFIED


def test_small_future_skew_age_at_original_deadline(event_factory, now, explicit_capabilities):
    event = event_factory(captured_at=now + timedelta(minutes=4))
    result = apply(MeshState(), event, now, explicit_capabilities)
    assert result.record.aging_deadline == now + timedelta(minutes=64)
    assert (
        not age_state(result.state, now=now + timedelta(minutes=63)).record(result.record.key).aged
    )
    assert age_state(result.state, now=now + timedelta(minutes=64)).record(result.record.key).aged


def test_verified_source_end_ages_observations_without_closing(
    event_factory, now, native_capabilities
):
    observation = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        context_changes={"session_id": "ended-session"},
    )
    result = apply(MeshState(), observation, now, native_capabilities)
    health = event_factory(
        native=True,
        event_kind="source.health",
        payload_changes={"session_ended": True},
        context_changes={"session_id": "ended-session"},
    )
    result = apply(result.state, health, now, native_capabilities)
    record = result.state.records[0]
    assert record.aged and record.source_state == SourceState.UNVERIFIED


def test_gate_never_creates_prompt_authority_or_execution(event_factory, now, native_capabilities):
    gate = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="gate_observed",
        snapshot_changes={"kind": "permission", "gate_kind": "platform_permission"},
    )
    result = apply(MeshState(), gate, now, native_capabilities)
    assert result.record.source_state == SourceState.UNVERIFIED
    assert result.record.execution_state == ExecutionState.NOT_OBSERVED
    assert result.record.source_request_id is None and not result.record.current_confirmed
    assert result.record.snapshot.source_expiry is None
    assert result.record.snapshot.authority_reference is None


def test_missing_native_scope_is_observation_boundary(event_factory, now, native_capabilities):
    no_id = event_factory(native=True, snapshot_changes={"native_reference": None})
    result = apply(MeshState(), no_id, now, native_capabilities)
    assert result.category == C.UNQUALIFIED and result.record is None
    assert "use_observation" in result.flags[0]
    wrong_context = event_factory(native=True, context_changes={"thread_id": "different"})
    assert apply(MeshState(), wrong_context, now, native_capabilities).category == C.UNQUALIFIED


def test_reconnect_epoch_does_not_change_native_identity(event_factory, now, native_capabilities):
    first = event_factory(
        native=True, context_changes={"connection_epoch": "epoch1"}, current=True, restored=True
    )
    second = event_factory(
        native=True,
        context_changes={"connection_epoch": "epoch2"},
        event_id="retry2",
        current=True,
        restored=True,
    )
    result = apply(MeshState(), first, now, native_capabilities)
    result = apply(result.state, second, now, native_capabilities)
    assert result.category == C.DUPLICATE
    assert len(result.state.records) == 1


def test_execution_separate_revision_stream_and_grouped_limit(
    event_factory, now, native_capabilities
):
    opened = event_factory(native=True, revision=8, current=True, restored=True)
    result = apply(MeshState(), opened, now, native_capabilities)
    running = event_factory(native=True, event_kind="execution.updated", revision=1)
    result = apply(result.state, running, now, native_capabilities)
    assert result.category == C.APPLY
    assert result.record.request_revision == 8 and result.record.execution_revision == 1
    assert result.record.execution_state == ExecutionState.RUNNING
    grouped = event_factory(
        native=True,
        event_kind="execution.updated",
        revision=2,
        payload_changes={"mapping": "grouped", "execution_state": "succeeded"},
    )
    result = apply(result.state, grouped, now, native_capabilities)
    assert result.category == C.UNQUALIFIED
    assert result.record.execution_state == ExecutionState.RUNNING
    assert "execution_mapping_unqualified" in result.record.limitations
    fresh = apply(MeshState(), grouped, now, native_capabilities)
    assert fresh.record.execution_state == ExecutionState.NOT_OBSERVED


def test_execution_terminal_no_resurrection(event_factory, now, native_capabilities):
    succeeded = event_factory(
        native=True,
        event_kind="execution.updated",
        payload_changes={"execution_state": "succeeded"},
    )
    result = apply(MeshState(), succeeded, now, native_capabilities)
    assert "opening_not_observed" in result.flags
    restart = event_factory(native=True, event_kind="execution.updated", revision=2)
    result = apply(result.state, restart, now, native_capabilities)
    assert result.category == C.CONFLICT
    assert result.record.execution_state == ExecutionState.SUCCEEDED


def test_qualification_uses_registered_producer_not_claimed_context(
    event_factory, now, native_capabilities
):
    forged = event_factory(producer_id="codex-native")
    result = apply(MeshState(), forged, now, native_capabilities)
    assert result.category == C.UNQUALIFIED and result.record is None
    assert result.flags == ("producer_kind_mismatch",)


def test_reducer_is_pure_and_values_immutable(event_factory, now, explicit_capabilities):
    empty = MeshState()
    result = apply(empty, event_factory(), now, explicit_capabilities)
    assert empty == MeshState()
    with pytest.raises(FrozenInstanceError):
        result.record.aged = True
    assert result == apply(empty, event_factory(), now, explicit_capabilities)


def test_capture_window_enforced_even_for_prevalidated_models(
    event_factory, now, explicit_capabilities
):
    for timestamp in [now - timedelta(days=31), now + timedelta(minutes=6)]:
        result = apply(
            MeshState(), event_factory(captured_at=timestamp), now, explicit_capabilities
        )
        assert result.category == C.UNQUALIFIED and not result.state.records


def test_persisted_fixture_replay(now, explicit_capabilities):
    path = Path(__file__).parent / "fixtures" / "events" / "producer-lifecycle.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    state = MeshState()
    results = []
    for raw in fixture["events"]:
        result = apply(state, validate_event(raw), now, explicit_capabilities)
        results.append(result.category.value)
        state = result.state
    assert results == fixture["expected_categories"]
    assert state.records[0].source_state == SourceState.AGENT_RESOLVED
    assert state.records[0].request_revision == 2
    assert len(state.events) == 3


def test_observation_identity_namespace_cannot_collide_with_real_requests(
    event_factory, now, explicit_capabilities
):
    observation = event_factory(event_kind="observation.recorded", event_id="e1")
    request = event_factory(request_id="observation:e1", event_id="e2")
    result = apply(MeshState(), observation, now, explicit_capabilities)
    result = apply(result.state, request, now, explicit_capabilities)
    assert result.category == C.APPLY
    assert len(result.state.records) == 2
    assert result.record.source_request_id == "observation:e1"


def test_same_content_higher_revision_cannot_unage_observation(
    event_factory, now, explicit_capabilities
):
    opening = event_factory(captured_at=now - timedelta(minutes=61))
    result = apply(MeshState(), opening, now, explicit_capabilities)
    same = event_factory(
        event_kind="request.updated", revision=2, captured_at=now, capture_policy_ref="new-policy"
    )
    result = apply(result.state, same, now, explicit_capabilities)
    assert result.category == C.APPLY
    assert result.record.request_revision == 2
    assert result.record.aged and result.record.captured_at == opening.captured_at
    assert result.record.capture_policy_ref is None
    assert "non_substantive_revision" in result.flags


def test_scoped_session_end_does_not_age_other_session(event_factory, now, native_capabilities):
    a = event_factory(
        native=True,
        event_kind="observation.recorded",
        event_id="a",
        evidence_class="prompt_confirmed",
        context_changes={"session_id": "A"},
    )
    b = event_factory(
        native=True,
        event_kind="observation.recorded",
        event_id="b",
        evidence_class="prompt_confirmed",
        context_changes={"session_id": "B"},
    )
    state = apply(MeshState(), a, now, native_capabilities).state
    state = apply(state, b, now, native_capabilities).state
    end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="end",
        context_changes={"session_id": "A"},
        payload_changes={"session_ended": True},
    )
    result = apply(state, end, now, native_capabilities)
    assert result.state.record(("codex-native", "", "a")).aged
    assert not result.state.record(("codex-native", "", "b")).aged


def test_unscoped_source_end_cannot_age_observations(event_factory, now, native_capabilities):
    observation = event_factory(
        native=True, event_kind="observation.recorded", evidence_class="prompt_confirmed"
    )
    state = apply(MeshState(), observation, now, native_capabilities).state
    end = event_factory(
        native=True,
        event_kind="source.health",
        payload_changes={"session_ended": True},
        context_changes={"thread_id": None},
    )
    result = apply(state, end, now, native_capabilities)
    assert "session_end_scope_unqualified" in result.flags
    assert not result.state.records[0].aged


def test_source_expiry_fact_does_not_synthesize_terminal_outcome(
    event_factory, now, native_capabilities
):
    event = event_factory(
        native=True,
        current=True,
        restored=True,
        snapshot_changes={"source_expiry": (now - timedelta(seconds=1)).isoformat()},
    )
    result = apply(MeshState(), event, now, native_capabilities)
    assert result.record.source_state == SourceState.PENDING
    assert result.record.current_confirmed


def test_native_continuity_frozen_fixture_replay(now, native_capabilities):
    path = Path(__file__).parent / "fixtures" / "events" / "native-continuity.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    state = MeshState()
    actual_categories, actual_states, actual_confirmation = [], [], []
    for raw in fixture["events"]:
        event = validate_event(raw)
        result = apply(state, event, max(now, event.captured_at), native_capabilities)
        state = result.state
        record = state.record(("codex-native", fixture["request_id"]))
        actual_categories.append(result.category.value)
        actual_states.append(record.source_state.value)
        actual_confirmation.append(record.current_confirmed)
    assert actual_categories == fixture["expected_categories"]
    assert actual_states == fixture["expected_states"]
    assert actual_confirmation == fixture["expected_confirmation"]
    assert state.records[0].execution_state == ExecutionState.NOT_OBSERVED


def test_orphan_execution_preserves_evidence_without_inventing_prompt_or_gate(
    event_factory, now, native_capabilities
):
    event = event_factory(native=True, event_kind="execution.updated")
    result = apply(MeshState(), event, now, native_capabilities)
    assert result.record.snapshot is None
    assert result.record.evidence_class.value == "source_authoritative"
    assert result.record.source_state == SourceState.UNVERIFIED
    assert not result.record.current_confirmed
    assert result.record.captured_at == now
    assert result.record.execution_state == ExecutionState.RUNNING


def test_reconciliation_cannot_cross_newer_disconnect_barrier(
    event_factory, now, native_capabilities
):
    opened = event_factory(native=True, current=True, restored=True)
    state = apply(MeshState(), opened, now, native_capabilities).state
    state = disconnect_source(state, "codex-native", now=now + timedelta(minutes=2))
    delayed = event_factory(
        native=True,
        event_kind="request.updated",
        revision=2,
        captured_at=now + timedelta(minutes=1),
        current=True,
        restored=True,
    )
    result = apply(state, delayed, now + timedelta(minutes=3), native_capabilities)
    assert result.category == C.APPLY
    assert not result.record.current_confirmed
    assert result.record.last_known_pending
    assert result.record.last_confirmed_at == now
    assert "reconciliation_predates_recovery_barrier" in result.flags
    fresh = event_factory(
        native=True,
        event_kind="request.updated",
        revision=3,
        captured_at=now + timedelta(minutes=4),
        current=True,
        restored=True,
    )
    result = apply(result.state, fresh, now + timedelta(minutes=4), native_capabilities)
    assert result.record.current_confirmed
    assert result.record.last_confirmed_at == now + timedelta(minutes=4)


def test_reordered_health_cannot_lower_recovery_barrier(event_factory, now, native_capabilities):
    state = disconnect_source(MeshState(), "codex-native", now=now + timedelta(minutes=2))
    old_health = event_factory(
        native=True,
        event_kind="source.health",
        captured_at=now + timedelta(minutes=1),
        payload_changes={"connection_state": "disconnected"},
    )
    result = apply(state, old_health, now + timedelta(minutes=3), native_capabilities)
    assert result.state.sources[0].recovery_barrier_at == now + timedelta(minutes=2)
    assert result.state.sources[0].captured_at == now + timedelta(minutes=2)
    old_snapshot = event_factory(
        native=True, current=True, restored=True, captured_at=now + timedelta(minutes=1, seconds=30)
    )
    result = apply(result.state, old_snapshot, now + timedelta(minutes=3), native_capabilities)
    assert not result.record.current_confirmed


def test_snapshot_at_disconnect_timestamp_cannot_claim_fresh_recovery(
    event_factory, now, native_capabilities
):
    state = disconnect_source(MeshState(), "codex-native", now=now)
    result = apply(
        state, event_factory(native=True, current=True, restored=True), now, native_capabilities
    )
    assert not result.record.current_confirmed


def test_execution_projection_cannot_supply_request_stream_history(
    event_factory, now, native_capabilities
):
    health = event_factory(native=True, event_kind="source.health")
    state = apply(MeshState(), health, now, native_capabilities).state
    execution = event_factory(native=True, event_kind="execution.updated")
    state = apply(state, execution, now, native_capabilities).state
    update = event_factory(native=True, event_kind="request.updated")
    result = apply(state, update, now, native_capabilities)
    assert "opening_not_observed" in result.flags
    assert not result.record.current_confirmed
    assert result.record.request_revision == result.record.execution_revision == 1
    assert result.record.execution_state == ExecutionState.RUNNING
    assert result.record.source_state == SourceState.PENDING


def test_request_projection_cannot_supply_execution_stream_history(
    event_factory, now, native_capabilities
):
    request = event_factory(native=True, current=True, restored=True)
    state = apply(MeshState(), request, now, native_capabilities).state
    execution = event_factory(native=True, event_kind="execution.updated")
    result = apply(state, execution, now, native_capabilities)
    assert "opening_not_observed" in result.flags
    assert result.record.request_revision == result.record.execution_revision == 1
    assert result.record.source_state == SourceState.PENDING
    assert result.record.current_confirmed
    assert result.record.execution_state == ExecutionState.RUNNING


@pytest.mark.parametrize("end_first", [False, True])
def test_source_end_replay_ages_matching_earlier_observation_in_either_order(
    event_factory, now, native_capabilities, end_first
):
    observation = event_factory(
        native=True,
        event_kind="observation.recorded",
        event_id="before-end",
        evidence_class="prompt_confirmed",
        captured_at=now + timedelta(minutes=1),
        context_changes={"session_id": "S"},
    )
    end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="ended",
        captured_at=now + timedelta(minutes=2),
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    events = [end, observation] if end_first else [observation, end]
    state = MeshState()
    for event in events:
        state = apply(state, event, now + timedelta(minutes=3), native_capabilities).state
    record = state.record(("codex-native", "", "before-end"))
    assert record.aged and record.visibility == VisibilityState.HISTORY
    assert record.source_state == SourceState.UNVERIFIED
    assert record.captured_at == now + timedelta(minutes=1)
    assert len(state.session_ends) == 1


def test_source_end_does_not_age_later_capture_with_same_scope(
    event_factory, now, native_capabilities
):
    end = event_factory(
        native=True,
        event_kind="source.health",
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    state = apply(MeshState(), end, now, native_capabilities).state
    later = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        captured_at=now + timedelta(minutes=1),
        context_changes={"session_id": "S"},
    )
    result = apply(state, later, now + timedelta(minutes=2), native_capabilities)
    assert not result.record.aged
    assert result.record.visibility == VisibilityState.ACTIVE


def test_session_end_scope_separates_source_instances(event_factory, now, native_capabilities):
    state = MeshState()
    for instance in ["A", "B"]:
        observation = event_factory(
            native=True,
            event_kind="observation.recorded",
            event_id=instance,
            evidence_class="prompt_confirmed",
            context_changes={"session_id": "S", "source_instance_id": instance},
        )
        state = apply(state, observation, now, native_capabilities).state
    end = event_factory(
        native=True,
        event_kind="source.health",
        context_changes={"session_id": "S", "source_instance_id": "A"},
        payload_changes={"session_ended": True},
    )
    result = apply(state, end, now, native_capabilities)
    assert result.state.record(("codex-native", "", "A")).aged
    assert not result.state.record(("codex-native", "", "B")).aged


def test_thread_only_end_is_not_qualified_session_end(event_factory, now, native_capabilities):
    observation = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        context_changes={"session_id": "still-running"},
    )
    state = apply(MeshState(), observation, now, native_capabilities).state
    end = event_factory(
        native=True, event_kind="source.health", payload_changes={"session_ended": True}
    )
    result = apply(state, end, now, native_capabilities)
    assert not result.state.records[0].aged
    assert "session_end_scope_unqualified" in result.flags
    assert not result.state.session_ends


def test_end_without_known_instance_cannot_cover_instance_scoped_observation(
    event_factory, now, native_capabilities
):
    observation = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        context_changes={"session_id": "S", "source_instance_id": "A"},
    )
    state = apply(MeshState(), observation, now, native_capabilities).state
    end = event_factory(
        native=True,
        event_kind="source.health",
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    result = apply(state, end, now, native_capabilities)
    assert not result.state.records[0].aged


def test_session_end_requires_manifest_required_context_scope(
    event_factory, now, native_capabilities
):
    scoped_capabilities = native_capabilities.model_copy(
        update={"identity_scope": ("native_request_id", "thread_id", "source_instance_id")}
    )
    end = event_factory(
        native=True,
        event_kind="source.health",
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    result = apply(MeshState(), end, now, scoped_capabilities)
    assert "session_end_scope_unqualified" in result.flags
    assert not result.state.session_ends


def test_turn_end_does_not_age_other_turn_and_session_end_covers_both_turns(
    event_factory, now, native_capabilities
):
    state = MeshState()
    for turn in ["turn1", "turn2"]:
        observation = event_factory(
            native=True,
            event_kind="observation.recorded",
            event_id=turn,
            evidence_class="prompt_confirmed",
            context_changes={"session_id": "S", "turn_id": turn},
        )
        state = apply(state, observation, now, native_capabilities).state
    turn_end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="turn-end",
        context_changes={"session_id": "S", "turn_id": "turn1"},
        payload_changes={"session_ended": True},
    )
    state = apply(state, turn_end, now, native_capabilities).state
    assert state.record(("codex-native", "", "turn1")).aged
    assert not state.record(("codex-native", "", "turn2")).aged
    session_end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="session-end",
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    state = apply(state, session_end, now, native_capabilities).state
    assert all(record.aged for record in state.records)


def test_compact_session_end_tombstone_is_sufficient_without_audit_or_old_records(
    event_factory, now, native_capabilities
):
    end = event_factory(
        native=True,
        event_kind="source.health",
        captured_at=now + timedelta(minutes=2),
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    ended = apply(MeshState(), end, now + timedelta(minutes=2), native_capabilities).state
    compact = MeshState(sources=ended.sources, session_ends=ended.session_ends)
    late = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        captured_at=now + timedelta(minutes=1),
        context_changes={"session_id": "S"},
    )
    result = apply(compact, late, now + timedelta(minutes=3), native_capabilities)
    assert result.record.aged and "source_session_ended" in result.flags
    assert result.record.source_state == SourceState.UNVERIFIED


def test_repeated_source_end_retains_maximum_covered_capture_time(
    event_factory, now, native_capabilities
):
    later_end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="end-later",
        captured_at=now + timedelta(minutes=3),
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    earlier_end = event_factory(
        native=True,
        event_kind="source.health",
        event_id="end-earlier",
        captured_at=now + timedelta(minutes=1),
        context_changes={"session_id": "S"},
        payload_changes={"session_ended": True},
    )
    state = apply(MeshState(), later_end, now + timedelta(minutes=4), native_capabilities).state
    state = apply(state, earlier_end, now + timedelta(minutes=4), native_capabilities).state
    assert len(state.session_ends) == 1
    assert state.session_ends[0].ended_at == later_end.captured_at
    late = event_factory(
        native=True,
        event_kind="observation.recorded",
        evidence_class="prompt_confirmed",
        captured_at=now + timedelta(minutes=2),
        context_changes={"session_id": "S"},
    )
    assert apply(state, late, now + timedelta(minutes=4), native_capabilities).record.aged


def test_orphan_request_cannot_establish_continuity_for_next_unreconciled_update(
    event_factory, now, native_capabilities
):
    health = event_factory(native=True, event_kind="source.health")
    state = apply(MeshState(), health, now, native_capabilities).state
    first = event_factory(native=True, event_kind="request.updated")
    result = apply(state, first, now, native_capabilities)
    assert result.record.connection_state == ConnectionState.UNKNOWN
    ordinary = event_factory(
        native=True,
        event_kind="request.updated",
        revision=2,
        captured_at=now + timedelta(minutes=1),
    )
    result = apply(result.state, ordinary, now + timedelta(minutes=1), native_capabilities)
    assert not result.record.current_confirmed
    restored = event_factory(
        native=True,
        event_kind="request.updated",
        revision=3,
        captured_at=now + timedelta(minutes=2),
        current=True,
        restored=True,
    )
    result = apply(result.state, restored, now + timedelta(minutes=2), native_capabilities)
    assert result.record.current_confirmed


def test_pruned_same_snapshot_higher_revision_retains_age_and_original_policy(
    event_factory, now, explicit_capabilities
):
    opening = event_factory(
        captured_at=now - timedelta(minutes=61), capture_policy_ref="old-policy"
    )
    result = apply(MeshState(), opening, now, explicit_capabilities)
    assert result.record.snapshot_digest is not None
    compact = replace(result.state, records=(replace(result.record, snapshot=None),), audit=())
    repeated = event_factory(
        event_kind="request.updated", revision=2, captured_at=now, capture_policy_ref="new-policy"
    )
    result = apply(compact, repeated, now, explicit_capabilities)
    assert result.record.aged and result.record.visibility == VisibilityState.HISTORY
    assert result.record.captured_at == opening.captured_at
    assert result.record.aging_deadline == opening.captured_at + timedelta(minutes=60)
    assert result.record.capture_policy_ref == "old-policy"
    assert "non_substantive_revision" in result.flags
    assert result.record.snapshot_digest == compact.records[0].snapshot_digest


def test_pruned_changed_snapshot_can_refresh_reported_evidence(
    event_factory, now, explicit_capabilities
):
    opening = event_factory(
        captured_at=now - timedelta(minutes=61), capture_policy_ref="old-policy"
    )
    result = apply(MeshState(), opening, now, explicit_capabilities)
    compact = replace(result.state, records=(replace(result.record, snapshot=None),), audit=())
    changed = event_factory(
        event_kind="request.updated",
        revision=2,
        captured_at=now,
        capture_policy_ref="new-policy",
        snapshot_changes={"summary": "Different material evidence"},
    )
    result = apply(compact, changed, now, explicit_capabilities)
    assert not result.record.aged and result.record.visibility == VisibilityState.ACTIVE
    assert result.record.captured_at == now
    assert result.record.aging_deadline == now + timedelta(minutes=60)
    assert result.record.capture_policy_ref == "new-policy"
    assert result.record.snapshot_digest != compact.records[0].snapshot_digest
    assert result.record.source_state == SourceState.UNVERIFIED


def test_pruned_terminal_never_reopens_on_changed_higher_revision(
    event_factory, now, explicit_capabilities
):
    closed = event_factory(event_kind="request.resolved", outcome="resolved", revision=2)
    result = apply(MeshState(), closed, now, explicit_capabilities)
    compact = replace(result.state, records=(replace(result.record, snapshot=None),), audit=())
    changed = event_factory(
        event_kind="request.updated",
        revision=3,
        snapshot_changes={"summary": "New content cannot resurrect this identity"},
    )
    result = apply(compact, changed, now, explicit_capabilities)
    assert result.category == C.CONFLICT
    assert result.record.terminal and result.record.snapshot is None
    assert result.record.snapshot_digest == compact.records[0].snapshot_digest


@pytest.mark.parametrize("order", list(permutations(("old_loss", "new_loss", "reconcile"))))
def test_health_loss_replay_permutations_preserve_later_qualified_reconciliation(
    event_factory, now, native_capabilities, order
):
    opened = event_factory(native=True, current=True, restored=True)
    state = apply(MeshState(), opened, now, native_capabilities).state
    events = {
        "old_loss": event_factory(
            native=True,
            event_kind="source.health",
            event_id="loss-1",
            captured_at=now + timedelta(minutes=1),
            payload_changes={"connection_state": "disconnected"},
        ),
        "new_loss": event_factory(
            native=True,
            event_kind="source.health",
            event_id="loss-2",
            captured_at=now + timedelta(minutes=2),
            payload_changes={"connection_state": "disconnected"},
        ),
        "reconcile": event_factory(
            native=True,
            event_kind="request.updated",
            revision=2,
            captured_at=now + timedelta(minutes=4),
            current=True,
            restored=True,
        ),
    }
    for name in order:
        state = apply(state, events[name], now + timedelta(minutes=5), native_capabilities).state
    record = state.record(("codex-native", opened.source_request_id))
    assert record.current_confirmed and record.connection_state == ConnectionState.CONTINUOUS
    assert record.last_confirmed_at == now + timedelta(minutes=4)
    assert record.source_state == SourceState.PENDING
    assert state.sources[0].recovery_barrier_at == now + timedelta(minutes=2)
    assert state.sources[0].captured_at == now + timedelta(minutes=2)


def test_delayed_health_loss_demotes_only_records_not_covered_by_later_confirmation(
    event_factory, now, native_capabilities
):
    a = event_factory(
        native=True,
        request_id="A",
        event_id="A-4",
        captured_at=now + timedelta(minutes=4),
        current=True,
        restored=True,
    )
    b = event_factory(
        native=True,
        request_id="B",
        event_id="B-2",
        captured_at=now + timedelta(minutes=2),
        current=True,
        restored=True,
    )
    state = apply(MeshState(), a, now + timedelta(minutes=5), native_capabilities).state
    state = apply(state, b, now + timedelta(minutes=5), native_capabilities).state
    loss = event_factory(
        native=True,
        event_kind="source.health",
        event_id="loss-3",
        captured_at=now + timedelta(minutes=3),
        payload_changes={"connection_state": "disconnected"},
    )
    state = apply(state, loss, now + timedelta(minutes=5), native_capabilities).state
    record_a = state.record(("codex-native", a.source_request_id))
    record_b = state.record(("codex-native", b.source_request_id))
    assert record_a.current_confirmed and record_a.connection_state == ConnectionState.CONTINUOUS
    assert not record_b.current_confirmed and record_b.last_known_pending
    assert record_b.connection_state == ConnectionState.DISCONNECTED
    assert record_a.last_confirmed_at == a.captured_at
    assert record_b.last_confirmed_at == b.captured_at
    assert state.sources[0].recovery_barrier_at == loss.captured_at


def test_historical_health_replay_never_reconfirms_an_already_unverified_record(
    event_factory, now, native_capabilities
):
    opened = event_factory(
        native=True, captured_at=now + timedelta(minutes=4), current=True, restored=True
    )
    state = apply(MeshState(), opened, now + timedelta(minutes=4), native_capabilities).state
    state = disconnect_source(state, "codex-native", now=now + timedelta(minutes=5))
    loss = event_factory(
        native=True,
        event_kind="source.health",
        captured_at=now + timedelta(minutes=3),
        payload_changes={"connection_state": "disconnected"},
    )
    state = apply(state, loss, now + timedelta(minutes=6), native_capabilities).state
    record = state.record(("codex-native", opened.source_request_id))
    assert not record.current_confirmed
    assert record.connection_state == ConnectionState.DISCONNECTED
    assert state.sources[0].recovery_barrier_at == now + timedelta(minutes=5)


def test_live_disconnect_helper_and_new_stream_gap_still_invalidate_confirmation(
    event_factory, now, native_capabilities
):
    opened = event_factory(
        native=True, captured_at=now + timedelta(minutes=4), current=True, restored=True
    )
    state = apply(MeshState(), opened, now + timedelta(minutes=4), native_capabilities).state
    live = disconnect_source(state, "codex-native", now=now + timedelta(minutes=5))
    assert not live.record(("codex-native", opened.source_request_id)).current_confirmed
    gap = event_factory(
        native=True,
        event_kind="request.updated",
        revision=3,
        captured_at=now + timedelta(minutes=2),
    )
    result = apply(state, gap, now + timedelta(minutes=5), native_capabilities)
    assert "revision_gap" in result.flags
    assert not result.record.current_confirmed
    assert result.record.connection_state == ConnectionState.GAPPED


def test_equal_time_health_loss_still_demotes_without_strictly_later_confirmation(
    event_factory, now, native_capabilities
):
    opened = event_factory(native=True, current=True, restored=True)
    state = apply(MeshState(), opened, now, native_capabilities).state
    loss = event_factory(
        native=True,
        event_kind="source.health",
        payload_changes={"connection_state": "disconnected"},
    )
    result = apply(state, loss, now, native_capabilities)
    record = result.state.record(("codex-native", opened.source_request_id))
    assert not record.current_confirmed
    assert record.last_confirmed_at == now


def test_historical_disconnect_does_not_replace_later_known_gap_connection(
    event_factory, now, native_capabilities
):
    opened = event_factory(native=True, current=True, restored=True)
    state = apply(MeshState(), opened, now, native_capabilities).state
    state = disconnect_source(
        state, "codex-native", now=now + timedelta(minutes=2), connection=ConnectionState.GAPPED
    )
    old_loss = event_factory(
        native=True,
        event_kind="source.health",
        captured_at=now + timedelta(minutes=1),
        payload_changes={"connection_state": "disconnected"},
    )
    result = apply(state, old_loss, now + timedelta(minutes=3), native_capabilities)
    record = result.state.record(("codex-native", opened.source_request_id))
    assert not record.current_confirmed
    assert record.connection_state == ConnectionState.GAPPED
    assert result.state.sources[0].connection_state == ConnectionState.GAPPED
    assert result.state.sources[0].captured_at == now + timedelta(minutes=2)
    assert result.state.sources[0].recovery_barrier_at == now + timedelta(minutes=2)


def test_original_review_r6_delayed_health_after_runtime_barrier_and_reconciliation(
    event_factory, now, native_capabilities
):
    state = disconnect_source(MeshState(), "codex-native", now=now + timedelta(minutes=2))
    snapshot = event_factory(
        native=True, captured_at=now + timedelta(minutes=4), current=True, restored=True
    )
    result = apply(state, snapshot, now + timedelta(minutes=4), native_capabilities)
    assert result.record.current_confirmed
    old_loss = event_factory(
        native=True,
        event_kind="source.health",
        captured_at=now + timedelta(minutes=1),
        payload_changes={"connection_state": "disconnected"},
    )
    state = apply(result.state, old_loss, now + timedelta(minutes=5), native_capabilities).state
    record = state.record(("codex-native", snapshot.source_request_id))
    assert record.current_confirmed
    assert record.connection_state == ConnectionState.CONTINUOUS
    assert record.last_confirmed_at == now + timedelta(minutes=4)
    assert state.sources[0].recovery_barrier_at == now + timedelta(minutes=2)
