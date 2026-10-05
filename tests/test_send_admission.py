"""Supported-runtime send admission; synthetic credentials/provider, real threads and SQLite."""

from datetime import UTC, datetime
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from decision_mesh.capture import atomic_write_owner_only
from decision_mesh.channels.telegram import TelegramOutcome, TelegramResult
from decision_mesh.contracts import EventKind, EvidenceClass, SourceCapabilities, validate_event
from decision_mesh.runtime import Runtime
from decision_mesh.settings import DestinationIdentity
from decision_mesh.setup import SetupState
from decision_mesh.storage import SQLiteStore
from decision_mesh.web import WebServiceError


@pytest.fixture
def runtime(tmp_path):
    root = tmp_path / "admission"
    with SQLiteStore(root / "decisionmesh.db") as store:
        store.register_source(
            SourceCapabilities(
                producer_id="send-admission-test",
                producer_kind="explicit",
                allowed_event_kinds=(EventKind.REQUEST_OPENED,),
                allowed_evidence_classes=(EvidenceClass.PRODUCER_REPORTED,),
            )
        )
        store.update_settings(
            0,
            {
                "channel_active": True,
                "destination": DestinationIdentity(chat_id=42, bot_id=7),
                "disclosure_fields": {"action"},
            },
            now=datetime.now(UTC),
        )
    atomic_write_owner_only(
        root / "setup.json",
        SetupState(
            stage="test_accepted",
            bot_id=7,
            recipient_id=42,
            credential_version="a" * 48,
        )
        .model_dump_json()
        .encode(),
    )
    vault = SimpleNamespace(
        get_version=lambda: "a" * 48,
        get_token=lambda: SecretStr("123:" + "A" * 35),
    )
    with Runtime(root, credentials=vault, poll_seconds=0.05) as active:
        assert active.service.policy_ready
        yield active


def ingest(runtime):
    event = validate_event(
        {
            "schema_version": 1,
            "producer_id": "send-admission-test",
            "event_id": "event-1",
            "event_kind": "request.opened",
            "captured_at": datetime.now(UTC).isoformat(),
            "source_context": {"producer_kind": "explicit"},
            "evidence_class": "producer_reported",
            "source_request_id": "question-1",
            "revision": 1,
            "capture_policy_ref": runtime.store.current_policy().policy_ref,
            "payload": {
                "snapshot": {
                    "kind": "question",
                    "title": "Synthetic admission test",
                    "summary": "Synthetic summary",
                    "action": "SYNTHETIC_PRIVATE_ACTION",
                }
            },
        }
    )
    return runtime.store.ingest(event, received_at=datetime.now(UTC))


def mutate(runtime, scenario):
    current = runtime.store.get_settings()
    if scenario == "revoke_disclosure":
        return runtime.service.update_settings(
            current.revision, {"disclosure_fields": set()}, now=datetime.now(UTC)
        )
    if scenario == "pause":
        return runtime.service.update_settings(
            current.revision, {"global_pause": True}, now=datetime.now(UTC)
        )
    off = runtime.service.update_settings(
        current.revision, {"channel_active": False}, now=datetime.now(UTC)
    )
    return runtime.service.update_settings(
        off.revision, {"channel_active": True}, now=datetime.now(UTC)
    )


def mutation_from_another_thread(runtime, scenario):
    results = []

    def change():
        try:
            mutate(runtime, scenario)
        except WebServiceError as exc:
            results.append(str(exc))
        else:
            results.append("committed")

    thread = Thread(target=change)
    thread.start()
    thread.join(2)
    assert not thread.is_alive()
    return results


@pytest.mark.parametrize("scenario", ["revoke_disclosure", "deactivate_reactivate", "pause"])
def test_runtime_serializes_mutation_from_final_render_through_provider(
    runtime, monkeypatch, scenario
):
    rendered, release_render, entered_provider, release_provider, completed = (
        Event() for _ in range(5)
    )
    sent, errors = [], []
    initial = runtime.store.get_settings()
    original_prepare, original_tick = runtime.delivery._prepare, runtime.delivery.tick

    def prepare(*args):
        prepared = original_prepare(*args)
        if prepared and prepared[0]["state"] == "inflight":
            rendered.set()
            assert release_render.wait(5)
        return prepared

    def tick(**kwargs):
        try:
            result = original_tick(**kwargs)
        except Exception as exc:
            errors.append((type(exc).__name__, str(exc)))
            completed.set()
            raise
        if result.attempted:
            completed.set()
        return result

    class Transport:
        def __init__(self, *args, **kwargs):
            pass

        def send_message(self, chat_id, text):
            sent.append((chat_id, text, runtime.store.get_settings()))
            entered_provider.set()
            assert release_provider.wait(5)
            return TelegramResult(TelegramOutcome.ACCEPTED, "synthetic", provider_message_id=1)

        def close(self):
            pass

    try:
        # Install hooks between complete runtime ticks; an already-running tick
        # would otherwise bypass the completion observer installed below.
        with runtime.service.delivery_gate, runtime.service.setup_gate:
            monkeypatch.setattr(runtime.delivery, "_prepare", prepare)
            monkeypatch.setattr(runtime.delivery, "tick", tick)
            runtime.delivery.channel.transport_factory = Transport
            receipt = ingest(runtime)
        assert rendered.wait(3)
        assert mutation_from_another_thread(runtime, scenario) == ["operation_busy"]
        assert runtime.store.get_settings() == initial and not sent
        release_render.set()
        assert entered_provider.wait(3)
        assert mutation_from_another_thread(runtime, scenario) == ["operation_busy"]
        assert runtime.store.get_settings() == initial
        # The provider call does not hold the SQLite writer or block local reads.
        with runtime.store.transaction() as db:
            assert db.execute("SELECT count(*) FROM dm_delivery_attempts").fetchone()[0] == 1
        assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 1
        release_provider.set()
        assert completed.wait(3)
        assert not errors, errors
        with runtime.service.setup_gate:
            occurrence = runtime.delivery.occurrences(receipt.record_id)[0]
            changed = mutate(runtime, scenario)
            assert changed != initial
        assert len(sent) == 1
        assert sent[0][0] == 42 and "SYNTHETIC_PRIVATE_ACTION" in sent[0][1]
        assert sent[0][2] == initial
        assert (
            runtime.delivery.occurrences(receipt.record_id)[0].occurrence_id
            == occurrence.occurrence_id
        )
        attempts = runtime.delivery.attempts(occurrence.occurrence_id)
        assert len(attempts) == 1 and attempts[0].outcome == "accepted"
    finally:
        release_render.set()
        release_provider.set()


@pytest.mark.parametrize("scenario", ["revoke_disclosure", "deactivate_reactivate", "pause"])
def test_mutation_completed_before_runtime_admission_is_observed(runtime, monkeypatch, scenario):
    completed = Event()
    sent = []
    original_tick = runtime.delivery.tick

    class Transport:
        def __init__(self, *args, **kwargs):
            pass

        def send_message(self, chat_id, text):
            sent.append((chat_id, text, runtime.store.get_settings()))
            return TelegramResult(TelegramOutcome.ACCEPTED, "synthetic", provider_message_id=1)

        def close(self):
            pass

    def tick(**kwargs):
        result = original_tick(**kwargs)
        completed.set()
        return result

    runtime.delivery.channel.transport_factory = Transport
    with runtime.service.setup_gate:
        receipt = ingest(runtime)
        changed = mutate(runtime, scenario)
        monkeypatch.setattr(runtime.delivery, "tick", tick)
        completed.clear()
    assert completed.wait(3)
    with runtime.service.setup_gate:
        assert runtime.store.get_settings() == changed
        attempts = runtime.delivery.attempts()
        if scenario == "revoke_disclosure":
            assert len(sent) == len(attempts) == 1
            assert "SYNTHETIC_PRIVATE_ACTION" not in sent[0][1]
            assert sent[0][2] == changed and attempts[0].outcome == "accepted"
        else:
            assert not sent and not attempts
        occurrences = runtime.delivery.occurrences(receipt.record_id)
        if scenario == "deactivate_reactivate":
            assert (
                not occurrences
            )  # Revoked eligibility is cancelled before worker materialization.
        else:
            assert len(occurrences) == 1
            assert occurrences[0].generation == changed.destination_generation
        assert runtime.store.get_record(receipt.record_id) is not None
