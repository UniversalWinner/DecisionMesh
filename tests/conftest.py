"""Reusable synthetic evidence; these fixtures do not qualify a real host."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from decision_mesh.contracts import (
    EventKind,
    EvidenceClass,
    NativeReference,
    SourceCapabilities,
    canonical_request_id,
    validate_event,
)

NOW = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def explicit_capabilities():
    return SourceCapabilities(
        producer_id="agent-local",
        producer_kind="explicit",
        allowed_event_kinds=tuple(EventKind),
        allowed_evidence_classes=(EvidenceClass.PRODUCER_REPORTED,),
    )


@pytest.fixture
def native_capabilities():
    return SourceCapabilities(
        producer_id="codex-native",
        producer_kind="native",
        allowed_event_kinds=tuple(EventKind),
        allowed_evidence_classes=tuple(EvidenceClass),
        identity_scope=("native_request_id", "thread_id"),
        authoritative_lifecycle=True,
        authoritative_current_snapshots=True,
        continuous_stream=True,
        one_to_one_execution=True,
    )


@pytest.fixture
def event_factory():
    def make(
        *,
        event_kind="request.opened",
        native=False,
        request_id="question-1",
        revision=1,
        event_id=None,
        captured_at=NOW,
        outcome=None,
        current=False,
        restored=False,
        snapshot_changes=None,
        payload_changes=None,
        context_changes=None,
        **top,
    ):
        snapshot = {"kind": "question", "title": "Choose a test target", "summary": "A or B?"}
        context = {"producer_kind": "native" if native else "explicit"}
        if native:
            reference = {"native_request_id": request_id, "thread_id": "thread-1"}
            request_id = canonical_request_id(
                NativeReference(**reference), ("native_request_id", "thread_id")
            )
            snapshot["native_reference"] = reference
            context["thread_id"] = "thread-1"
        snapshot.update(snapshot_changes or {})
        context.update(context_changes or {})
        payload = {
            "snapshot": snapshot,
            "authoritative_current": current,
            "continuity_restored": restored,
        }
        if outcome is not None:
            payload["outcome"] = outcome
        if event_kind == "execution.updated":
            payload = {
                "execution_id": "execution-1",
                "execution_state": "running",
                "mapping": "one_to_one",
                "native_reference": snapshot.get("native_reference"),
            }
        if event_kind == "source.health":
            payload = {"connection_state": "continuous"}
        payload.update(payload_changes or {})
        uncorrelated = event_kind in {"source.health", "observation.recorded"}
        raw = {
            "schema_version": 1,
            "producer_id": "codex-native" if native else "agent-local",
            "event_id": event_id or f"{event_kind}:{revision}",
            "event_kind": event_kind,
            "captured_at": captured_at.isoformat(),
            "source_context": context,
            "evidence_class": "source_authoritative" if native else "producer_reported",
            "source_request_id": None if uncorrelated else request_id,
            "revision": None if uncorrelated else revision,
            "payload": payload,
        }
        raw.update(top)
        return validate_event(deepcopy(raw))

    return make
