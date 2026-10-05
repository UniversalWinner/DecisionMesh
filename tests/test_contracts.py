import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from decision_mesh.contracts import (
    MAX_EVENT_BYTES,
    NativeReference,
    SourceCapabilities,
    canonical_request_id,
    event_digest,
    event_schema,
    snapshot_digest,
    validate_event,
)


def raw_event(event_factory, **kwargs):
    return event_factory(**kwargs).model_dump(mode="json")


@pytest.mark.parametrize(
    "kind,outcome",
    [
        ("request.opened", None),
        ("request.updated", None),
        ("request.resolved", "resolved"),
        ("request.withdrawn", "withdrawn"),
        ("observation.recorded", None),
    ],
)
def test_explicit_event_families(event_factory, kind, outcome):
    event = event_factory(event_kind=kind, outcome=outcome)
    assert event.event_kind == kind
    assert event_digest(validate_event(event.model_dump_json())) == event_digest(event)


@pytest.mark.parametrize(
    "kind,outcome",
    [
        ("request.corrected", "answered"),
        ("request.resolved", "closed_unknown"),
        ("execution.updated", None),
        ("source.health", None),
    ],
)
def test_native_event_families(event_factory, kind, outcome):
    assert event_factory(event_kind=kind, native=True, outcome=outcome).event_kind == kind


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("schema_version", "1"),
        ("revision", True),
        ("revision", "1"),
        ("revision", 0),
        ("revision", 1.2),
        ("producer_id", 123),
        ("event_id", "a" * 129),
        ("producer_id", ""),
        ("event_kind", "request.approved"),
        ("captured_at", "2026-10-04T10:00:00"),
        ("captured_at", 12345),
        ("captured_at", None),
        ("mystery", "sensitive"),
    ],
)
def test_strict_schema_and_primitives(event_factory, field, value):
    raw = raw_event(event_factory)
    raw[field] = value
    with pytest.raises((ValidationError, ValueError)):
        validate_event(raw)


@pytest.mark.parametrize("field,limit", [("title", 160), ("summary", 2048), ("reason", 4096)])
def test_snapshot_bounds(event_factory, field, limit):
    raw = raw_event(event_factory)
    raw["payload"]["snapshot"][field] = "a" * limit
    validate_event(raw)
    raw["payload"]["snapshot"][field] += "a"
    with pytest.raises(ValidationError):
        validate_event(raw)


def test_unknown_nested_data_and_bool_coercion(event_factory):
    raw = raw_event(event_factory)
    raw["payload"]["transcript"] = "secret"
    with pytest.raises(ValidationError):
        validate_event(raw)
    raw["payload"].pop("transcript")
    raw["payload"]["continuity_restored"] = 1
    with pytest.raises(ValidationError):
        validate_event(raw)


def test_schema_version_is_required(event_factory):
    raw = raw_event(event_factory)
    del raw["schema_version"]
    with pytest.raises(ValidationError):
        validate_event(raw)


def test_body_cap_before_parse_and_utf8(event_factory):
    with pytest.raises(ValueError, match="256 KiB"):
        validate_event(b" " * (MAX_EVENT_BYTES + 1))
    with pytest.raises(ValidationError):
        validate_event(b"\xff")
    raw = raw_event(event_factory)
    raw["payload"]["snapshot"]["summary"] = "é" * 2048
    assert (
        validate_event(json.dumps(raw, ensure_ascii=False)).payload.snapshot.summary == "é" * 2048
    )


def test_time_acceptance_and_offset_normalization(event_factory, now):
    raw = raw_event(event_factory)
    raw["captured_at"] = "2026-10-04T15:30:00+05:30"
    assert validate_event(raw, now=now).captured_at == now
    validate_event(raw_event(event_factory, captured_at=now + timedelta(minutes=5)), now=now)
    for captured in [now + timedelta(minutes=5, seconds=1), now - timedelta(days=30, seconds=1)]:
        with pytest.raises(ValueError):
            validate_event(raw_event(event_factory, captured_at=captured), now=now)


def test_explicit_cannot_claim_host_authority_or_provenance(event_factory):
    raw = raw_event(event_factory)
    raw["evidence_class"] = "source_authoritative"
    with pytest.raises(ValidationError):
        validate_event(raw)
    raw["evidence_class"] = "producer_reported"
    raw["payload"]["snapshot"]["provenance"] = [{"field": "title", "asserted_by": "host"}]
    with pytest.raises(ValidationError):
        validate_event(raw)
    raw["payload"]["snapshot"]["provenance"] = []
    raw["payload"]["snapshot"]["authority_reference"] = {"quote": "Allow it", "asserted_by": "host"}
    with pytest.raises(ValidationError):
        validate_event(raw)


def test_explicit_terminals_are_agent_reports(event_factory):
    with pytest.raises(ValidationError):
        event_factory(event_kind="request.resolved", outcome="answered")


def test_native_identity_scope_is_complete_and_stable():
    reference = NativeReference(native_request_id="n1", thread_id="t1")
    assert canonical_request_id(
        reference, ("native_request_id", "thread_id")
    ) == canonical_request_id(reference, ("thread_id", "native_request_id"))
    assert canonical_request_id(
        reference, ("native_request_id", "thread_id")
    ) != canonical_request_id(
        NativeReference(native_request_id="n1", thread_id="t2"), ("native_request_id", "thread_id")
    )
    for scope in [
        ("native_request_id", "session_id"),
        (),
        ("native_request_id", "native_request_id"),
    ]:
        with pytest.raises(ValueError):
            canonical_request_id(reference, scope)


def test_schema_generation_is_discriminated_and_forbids_extra_fields():
    schema = event_schema()
    assert schema["discriminator"]["propertyName"] == "event_kind"
    assert set(schema["discriminator"]["mapping"]) == {
        "observation.recorded",
        "request.opened",
        "request.updated",
        "request.resolved",
        "request.withdrawn",
        "request.corrected",
        "execution.updated",
        "source.health",
    }
    assert schema["$defs"]["SourceContext"]["additionalProperties"] is False
    assert schema["$defs"]["DecisionSnapshot"]["properties"]["title"]["maxLength"] == 160


def test_models_are_frozen(event_factory):
    event = event_factory()
    with pytest.raises(ValidationError):
        event.payload.snapshot.title = "changed"
    assert isinstance(event.payload.snapshot.provenance, tuple)


def test_registered_explicit_capabilities_cannot_self_upgrade():
    with pytest.raises(ValidationError):
        SourceCapabilities(
            producer_id="p",
            producer_kind="explicit",
            allowed_event_kinds=(),
            allowed_evidence_classes=("source_authoritative",),
        )


@pytest.mark.parametrize("field", ["captured_at", "occurred_at", "source_expiry"])
@pytest.mark.parametrize("timestamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_unrepresentable_utc_timestamp_is_validation_failure(event_factory, now, field, timestamp):
    raw = raw_event(event_factory)
    if field == "source_expiry":
        raw["payload"]["snapshot"][field] = timestamp
    else:
        raw[field] = timestamp
    with pytest.raises((ValidationError, ValueError)):
        validate_event(raw, now=now)


def test_snapshot_digest_is_canonical_across_transport_json_key_order(event_factory):
    event = event_factory()
    raw = event.model_dump(mode="json")
    raw["payload"]["snapshot"] = dict(reversed(list(raw["payload"]["snapshot"].items())))
    replay = validate_event(raw)
    assert snapshot_digest(event.payload.snapshot) == snapshot_digest(replay.payload.snapshot)
    changed = event_factory(snapshot_changes={"summary": "Changed material evidence"})
    assert snapshot_digest(event.payload.snapshot) != snapshot_digest(changed.payload.snapshot)
