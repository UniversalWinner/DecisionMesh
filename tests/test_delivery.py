"""Real temporary SQLite + fake provider/clock; no native support qualification."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import timedelta

import pytest

from decision_mesh.channels.telegram import TelegramOutcome, TelegramResult
from decision_mesh.delivery import RETRY_SECONDS, DeliveryError, DeliveryWorker
from decision_mesh.settings import DeliveryMode
from decision_mesh.storage import SQLiteStore


class FakeClock:
    def __init__(self, now):
        self.wall, self.elapsed = now, 0.0

    def utcnow(self):
        return self.wall

    def monotonic(self):
        return self.elapsed

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.elapsed += seconds


class FakeChannel:
    def __init__(self, *results):
        self.results, self.calls, self.callback = list(results), [], None

    def send_message(self, chat_id, text):
        self.calls.append((chat_id, text))
        if self.callback:
            self.callback()
        result = (
            self.results.pop(0)
            if self.results
            else TelegramResult(TelegramOutcome.ACCEPTED, "ok", len(self.calls))
        )
        if isinstance(result, Exception):
            raise result
        return result


def failure(outcome=TelegramOutcome.DEFINITE_FAILURE, *, retry_after=None):
    return TelegramResult(
        outcome, "PRIVATE PROVIDER ERROR MUST NOT BE STORED", retry_after=retry_after
    )


@dataclass
class Harness:
    store: SQLiteStore
    worker: DeliveryWorker
    clock: FakeClock
    channel: FakeChannel
    factory: object

    def settings(self, **changes):
        return self.store.update_settings(
            self.store.get_settings().revision, changes, now=self.clock.utcnow()
        )

    def add(self, request_id="q1", **kwargs):
        kwargs.setdefault("event_id", f"{request_id}:{kwargs.get('revision', 1)}")
        kwargs.setdefault("capture_policy_ref", self.store.current_policy().policy_ref)
        kwargs.setdefault("captured_at", self.clock.utcnow())
        event = self.factory(request_id=request_id, **kwargs)
        return self.store.ingest(event, received_at=self.clock.utcnow())

    def restart_worker(self):
        self.worker = DeliveryWorker(self.store, self.channel, clock=self.clock, jitter=lambda _: 0)
        return self.worker


@pytest.fixture
def h(tmp_path, now, event_factory, explicit_capabilities):
    store = SQLiteStore(tmp_path / "data" / "mesh.db", now=now)
    store.register_source(explicit_capabilities)
    store.update_settings(
        0,
        {"channel_active": True, "destination": {"chat_id": 123, "bot_id": 456}},
        now=now - timedelta(seconds=1),
    )
    clock, channel = FakeClock(now), FakeChannel()
    harness = Harness(
        store,
        DeliveryWorker(store, channel, clock=clock, jitter=lambda _: 0),
        clock,
        channel,
        event_factory,
    )
    yield harness
    store.close()


def test_immediate_commit_before_io_no_transaction_and_source_unchanged(h):
    receipt = h.add()
    source = h.store.get_record(receipt.record_id).projection

    def inspect():
        assert h.worker.attempts()[0].outcome == "started"
        # This is the same serialized public writer, not an unrelated connection.
        with h.store.transaction() as db:
            assert db.execute("SELECT count(*) FROM dm_delivery_attempts").fetchone()[0] == 1

    h.channel.callback = inspect
    result = h.worker.tick()
    assert (result.attempted, result.accepted) == (1, 1)
    assert h.worker.occurrences()[0].state == "accepted"
    assert h.worker.attempts()[0].provider_message_id == 1
    assert h.store.get_record(receipt.record_id).projection == source
    assert "Agent-reported question (not verified)" in h.channel.calls[0][1]
    assert "Choose a test target" not in h.channel.calls[0][1]


def test_accepted_restart_settings_mode_and_nonsubstantive_revision_do_not_repeat(h):
    receipt = h.add()
    h.worker.tick()
    original = h.worker.occurrences()[0]
    h.settings(delivery_mode="digest", telegram_layout="friendly", disclosure_fields={"action"})
    h.clock.advance(1)
    h.add(revision=2, event_kind="request.updated")
    h.restart_worker().tick()
    h.clock.advance(10000)
    h.worker.tick()
    assert len(h.channel.calls) == 1
    assert h.worker.occurrences()[0].occurrence_id == original.occurrence_id
    assert h.store.get_record(receipt.record_id).projection.captured_at == original.captured_at


def test_substantive_update_cancels_unsent_old_and_creates_new(h):
    h.add()
    h.worker.tick(max_attempts=0)
    h.clock.advance(1)
    h.add(revision=2, event_kind="request.updated", snapshot_changes={"title": "New decision"})
    h.worker.tick()
    assert len(h.channel.calls) == 1
    assert [r.state for r in h.worker.occurrences()] == ["cancelled", "accepted"]


@pytest.mark.parametrize(
    "outcome", [TelegramOutcome.DEFINITE_FAILURE, TelegramOutcome.AMBIGUOUS_OUTCOME]
)
def test_six_attempts_persist_exact_deadlines_and_manual_is_one_extra(h, outcome):
    h.channel.results = [failure(outcome) for _ in range(8)]
    h.add()
    h.worker.tick()
    occurrence = h.worker.occurrences()[0].occurrence_id
    for index, delay in enumerate(RETRY_SECONDS):
        attempt = h.worker.attempts()[-1]
        assert (attempt.next_attempt_at - attempt.finished_at).total_seconds() == delay
        h.clock.advance(delay - 0.01)
        assert h.worker.tick().attempted == 0
        h.clock.advance(0.01)
        assert h.worker.tick().attempted == 1
        if index == 1:
            h.restart_worker()
    assert len(h.worker.attempts()) == 6
    h.clock.advance(1000)
    assert h.worker.tick().attempted == 0
    if outcome == TelegramOutcome.AMBIGUOUS_OUTCOME:
        with pytest.raises(DeliveryError, match="duplicate_acknowledgement_required"):
            h.worker.manual_retry(occurrence)
    h.worker.manual_retry(occurrence, acknowledge_duplicate=True)
    h.worker.manual_retry(occurrence, acknowledge_duplicate=True)
    assert h.worker.tick().attempted == 1
    assert h.worker.attempts()[-1].manual
    h.clock.advance(2000)
    assert h.worker.tick().attempted == 0
    assert len(h.worker.attempts()) == 7
    assert len(h.worker.occurrences()) == 1


def test_jitter_bound_and_longer_retry_after(h):
    h.worker.jitter = lambda _: 0.75
    h.channel.results = [failure(retry_after=20), failure()]
    h.add()
    h.worker.tick()
    assert (h.worker.attempts()[0].next_attempt_at - h.clock.utcnow()).total_seconds() == 20
    h.clock.advance(20)
    h.worker.tick()
    assert (h.worker.attempts()[-1].next_attempt_at - h.clock.utcnow()).total_seconds() == 15.75


def test_rate_limit_blocks_following_route_and_survives_restart(h):
    h.channel.results = [failure(TelegramOutcome.RATE_LIMITED, retry_after=100)]
    h.add("a")
    h.add("b")
    assert h.worker.tick().attempted == 1
    h.restart_worker()
    h.clock.advance(99)
    assert h.worker.tick().attempted == 0
    h.clock.advance(1)
    assert h.worker.tick().accepted == 2


@pytest.mark.parametrize(
    "outcome", [TelegramOutcome.AUTH_FAILURE, TelegramOutcome.RECIPIENT_FAILURE]
)
def test_auth_recipient_suspend_retains_generation_and_requires_resume(h, outcome):
    h.channel.results = [failure(outcome)]
    h.add("a")
    h.add("b")
    generation = h.store.get_settings().destination_generation
    assert h.worker.tick().attempted == 1
    assert h.store.get_settings().provider_suspended
    h.restart_worker()
    h.settings(provider_suspended=False)
    assert h.worker.tick().attempted == 0
    h.worker.resume_route()
    assert h.worker.tick().accepted == 1
    assert h.store.get_settings().destination_generation == generation


def test_retry_disclosure_revocation_expansion_and_no_retry_body_storage(h):
    h.settings(disclosure_fields={"action"})
    h.add(snapshot_changes={"action": "PRIVATE ACTION", "reason": "PRIVATE REASON"})
    h.channel.results = [failure(), failure()]
    h.worker.tick()
    assert "PRIVATE ACTION" in h.channel.calls[-1][1]
    h.settings(disclosure_fields={"reason"})
    h.clock.advance(5)
    h.worker.tick()
    assert "PRIVATE ACTION" not in h.channel.calls[-1][1]
    assert "PRIVATE REASON" not in h.channel.calls[-1][1]
    h.settings(disclosure_fields={"action", "reason"})
    h.clock.advance(15)
    h.worker.tick()
    assert "PRIVATE ACTION" in h.channel.calls[-1][1]
    assert "PRIVATE REASON" not in h.channel.calls[-1][1]
    with h.store.read_snapshot() as db:
        tables = [
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'dm_delivery_%'"
            )
        ]
        persisted = repr(
            [tuple(row) for table in tables for row in db.execute(f"SELECT * FROM {table}")]
        )
    assert "PRIVATE" not in persisted


def test_enqueue_grant_is_upper_bound_even_if_capture_grant_larger(h):
    h.settings(disclosure_fields={"action"})
    h.add(snapshot_changes={"action": "PRIVATE ACTION"})
    h.settings(disclosure_fields=set())
    h.worker.tick(max_attempts=0)
    h.settings(disclosure_fields={"action"})
    h.worker.tick()
    assert "PRIVATE ACTION" not in h.channel.calls[0][1]


def test_destination_deactivate_reactivate_cancels_and_old_spool_stays_local(h):
    policy = h.store.current_policy()
    h.add("queued")
    h.worker.tick(max_attempts=0)
    h.settings(channel_active=False)
    h.settings(channel_active=True)
    old = h.add("old-spool", capture_policy_ref=policy.policy_ref)
    h.worker.tick()
    assert h.channel.calls == []
    assert h.worker.occurrences()[0].state == "cancelled"
    assert h.worker.include_current([old.record_id])
    h.worker.tick()
    assert len(h.channel.calls) == 1


@pytest.mark.parametrize("policy", [None, "unknown-policy"])
def test_missing_policy_stays_local_until_explicit_minimal_inclusion(h, policy):
    h.settings(disclosure_fields={"action"})
    r = h.add(capture_policy_ref=policy, snapshot_changes={"action": "PRIVATE ACTION"})
    assert h.worker.tick().attempted == 0
    ids = h.worker.include_current([r.record_id])
    assert h.worker.include_current([r.record_id]) == ids
    assert h.worker.tick().accepted == 1
    assert "PRIVATE ACTION" not in h.channel.calls[0][1]


def test_resolved_before_send_and_between_calls_never_changes_source(h):
    first, second = h.add("a"), h.add("b")
    h.worker.tick(max_attempts=0)
    h.add("a", revision=2, event_kind="request.resolved", outcome="resolved")
    before = h.store.get_record(first.record_id).projection
    assert h.worker.tick().accepted == 1
    assert h.store.get_record(first.record_id).projection == before
    assert h.worker.occurrences(first.record_id)[0].state == "cancelled"
    assert h.worker.occurrences(second.record_id)[0].state == "accepted"


def test_gate_only_and_last_known_native_never_send(h, native_capabilities):
    h.store.register_source(native_capabilities, enabled=True, qualified=True)
    h.add("gate", native=True, event_kind="observation.recorded", evidence_class="gate_observed")
    h.add("pending", native=True, current=True, restored=True)
    h.worker.tick(max_attempts=0)
    h.store.close()
    h.store = SQLiteStore(h.store.path, now=h.clock.utcnow())
    h.restart_worker().tick()
    assert h.channel.calls == []


def test_seen_is_not_suppression_and_snooze_one_reminder(h):
    r = h.add()
    h.store.set_record_metadata(r.record_id, seen=True, now=h.clock.utcnow())
    assert h.worker.tick().accepted == 1
    h.store.set_record_metadata(
        r.record_id, snoozed_until=h.clock.utcnow() + timedelta(minutes=10), now=h.clock.utcnow()
    )
    h.worker.tick()
    h.clock.advance(600)
    assert h.worker.tick().accepted == 1
    h.restart_worker().tick()
    assert len(h.channel.calls) == 2
    assert {r.kind for r in h.worker.occurrences()} == {"initial", "snooze_reminder"}


def test_suppress_cancels_unattempted_and_aged_snooze_no_reminder(h):
    r = h.add("hidden")
    h.worker.tick(max_attempts=0)
    h.store.set_record_metadata(r.record_id, suppressed=True, now=h.clock.utcnow())
    second = h.add("aged")
    h.worker.tick()
    h.store.set_record_metadata(
        second.record_id, snoozed_until=h.clock.utcnow() + timedelta(hours=2), now=h.clock.utcnow()
    )
    h.clock.advance(7200)
    h.worker.tick()
    assert len(h.channel.calls) == 1
    assert len(h.worker.occurrences(second.record_id)) == 1


def test_delayed_import_and_pause_aging_batch_once_original_time(h):
    h.settings(global_pause=True)
    h.add("queued")
    h.worker.tick()
    h.clock.advance(7200)
    h.add("delayed", captured_at=h.clock.utcnow() - timedelta(hours=2))
    h.settings(global_pause=False)
    assert h.worker.tick().accepted == 1
    text = h.channel.calls[0][1]
    assert "HISTORICAL" in text and "may already be answered" in text
    assert "10:00" in text and "age 120m" in text
    assert {r.kind for r in h.worker.occurrences()} == {"historical_summary"}
    h.restart_worker().tick()
    assert len(h.channel.calls) == 1


def test_aging_failed_attempt_retains_identity_and_budget(h):
    h.channel.results = [failure()]
    h.add()
    h.worker.tick()
    original = h.worker.occurrences()[0]
    h.clock.advance(4000)
    h.worker.tick()
    assert h.worker.occurrences()[0].occurrence_id == original.occurrence_id
    assert h.worker.occurrences()[0].kind == "initial"
    assert len(h.worker.attempts()) == 2
    assert "Historical observation; may already be answered" in h.channel.calls[-1][1]


def test_digest_empty_interval_forward_sleep_one_catchup_and_backward_clock(h):
    h.settings(delivery_mode=DeliveryMode.DIGEST, digest_interval_minutes=1)
    h.worker.tick()
    h.clock.advance(60)
    assert h.worker.tick().attempted == 0
    h.add("a")
    h.add("b")
    h.clock.advance(600)
    assert h.worker.tick().accepted == 1
    assert "observed since the last digest" in h.channel.calls[0][1]
    h.clock.wall -= timedelta(days=1)
    h.clock.elapsed += 60
    assert h.worker.tick().attempted == 0
    assert len(h.channel.calls) == 1


def test_digest_split_receipts_retry_only_failed_part_and_mode_switch(h):
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    for index in range(5):
        h.add(f"q{index}")
    h.worker.tick()
    h.clock.advance(60)
    h.channel.results = [TelegramResult(TelegramOutcome.ACCEPTED, "ok", 1), failure()]
    result = h.worker.tick()
    assert result.attempted == 2 and result.accepted == 1
    old_ids = {r.occurrence_id for r in h.worker.occurrences()}
    success_text = h.channel.calls[0][1]
    h.settings(delivery_mode="immediate", telegram_layout="friendly")
    h.clock.advance(5)
    assert h.worker.tick().accepted == 1
    assert {r.occurrence_id for r in h.worker.occurrences()} == old_ids
    for r in h.worker.occurrences():
        ref = h.store.get_record(r.record_id).short_reference
        assert len(h.worker.attempts(r.occurrence_id)) == (1 if ref in success_text else 2)


def test_mode_switch_only_never_attempted_members(h):
    h.add("a")
    h.add("b")
    h.worker.tick(max_attempts=0)
    ids = {r.occurrence_id for r in h.worker.occurrences()}
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    assert h.worker.tick().attempted == 0
    h.clock.advance(60)
    assert h.worker.tick().accepted == 1
    assert {r.occurrence_id for r in h.worker.occurrences()} == ids


def test_restore_copied_extension_occurrences_suppressed(h, tmp_path):
    h.add()
    h.worker.tick(max_attempts=0)
    backup = h.store.backup(tmp_path / "backup" / "mesh.db")
    h.store.close()
    h.clock.advance(30)
    h.store = SQLiteStore.restore_backup(
        backup, tmp_path / "restored" / "mesh.db", now=h.clock.utcnow()
    )
    h.settings(channel_active=True)
    h.restart_worker().tick()
    assert h.channel.calls == []
    assert all(r.state == "suppressed" for r in h.worker.occurrences())
    old_record = h.worker.occurrences()[0].record_id
    h.worker.include_current([old_record])
    assert h.worker.tick().accepted == 1
    assert "may already be answered" in h.channel.calls[0][1]


def test_channel_exception_is_ambiguous_and_redacted(h):
    h.channel.results = [RuntimeError("PRIVATE SECRET")]
    h.add()
    h.worker.tick()
    assert h.worker.attempts()[0].outcome == "outcome_unknown"
    assert "PRIVATE" not in repr(h.worker.attempts())


def test_unsent_snooze_ending_after_age_is_hide_without_historical_send(h):
    r = h.add()
    h.store.set_record_metadata(
        r.record_id, snoozed_until=h.clock.utcnow() + timedelta(hours=2), now=h.clock.utcnow()
    )
    h.worker.tick()
    h.clock.advance(7200)
    assert h.worker.tick().attempted == 0
    assert h.channel.calls == []
    assert h.worker.occurrences()[0].reason == "snooze_hide"


def test_manual_digest_retry_only_selected_member(h):
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    first, second = h.add("a"), h.add("b")
    h.worker.tick()
    h.clock.advance(60)
    h.worker.tick()
    occurrence = h.worker.occurrences(first.record_id)[0]
    with pytest.raises(DeliveryError, match="duplicate_acknowledgement_required"):
        h.worker.manual_retry(occurrence.occurrence_id)
    h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)
    assert h.worker.tick().accepted == 1
    second_ref = h.store.get_record(second.record_id).short_reference
    assert second_ref not in h.channel.calls[-1][1]
    assert len(h.worker.attempts(h.worker.occurrences(second.record_id)[0].occurrence_id)) == 1


def test_revoke_disclosure_between_attempt_commit_and_io_renders_again(h):
    h.settings(disclosure_fields={"action"})
    h.add(snapshot_changes={"action": "PRIVATE ACTION"})

    def revoke(point):
        if point == "attempt_committed":
            h.settings(disclosure_fields=set())

    h.worker.fault_hook = revoke
    assert h.worker.tick().accepted == 1
    assert "PRIVATE ACTION" not in h.channel.calls[0][1]


def test_disable_between_attempt_commit_and_io_records_not_sent(h):
    h.add()

    def disable(point):
        if point == "attempt_committed":
            h.settings(channel_active=False)

    h.worker.fault_hook = disable
    h.worker.tick()
    assert h.channel.calls == []
    assert h.worker.attempts()[0].outcome == "not_sent"
    h.worker.tick()
    assert h.worker.occurrences()[0].state == "cancelled"


def test_backward_clock_retry_uses_live_monotonic_time(h):
    h.add()
    h.channel.results = [failure()]
    h.worker.tick()
    h.clock.wall -= timedelta(days=1)
    h.clock.elapsed += 5
    assert h.worker.tick().accepted == 1


def test_clock_jump_and_aging_cannot_unage_or_send_burst(h):
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    r = h.add()
    h.worker.tick()
    h.clock.wall += timedelta(days=1)
    assert h.worker.tick().accepted == 1
    assert h.store.get_record(r.record_id).projection.aged
    h.clock.wall -= timedelta(days=1)
    assert h.worker.tick().attempted == 0
    assert h.store.get_record(r.record_id).projection.aged


def test_resolution_during_previous_provider_call_stops_following_send(h):
    h.add("a")
    h.add("b")
    h.channel.callback = lambda: h.add(
        "b", revision=2, event_kind="request.withdrawn", outcome="withdrawn"
    )
    assert h.worker.tick().accepted == 1
    assert len(h.channel.calls) == 1


def test_digest_historical_section_distinct_and_accepted_not_recreated(h):
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    h.add("old")
    h.worker.tick()
    h.clock.advance(4000)
    h.add("new")
    assert h.worker.tick().accepted == 2
    assert sum("HISTORICAL" in text for _, text in h.channel.calls) == 1
    assert sum("observed since the last digest" in text for _, text in h.channel.calls) == 1
    h.worker.tick()
    assert len(h.channel.calls) == 2


def test_digest_due_persists_on_restart_and_catches_up_once(h):
    h.settings(delivery_mode="digest", digest_interval_minutes=1)
    h.add()
    h.worker.tick()
    h.clock.advance(600)
    h.restart_worker()
    assert h.worker.tick().accepted == 1
    assert h.worker.tick().attempted == 0


def test_recovered_started_attempt_uses_original_persisted_deadline(h):
    class Crash(BaseException):
        pass

    h.add()

    def crash(point):
        if point == "attempt_committed":
            raise Crash()

    h.worker.fault_hook = crash
    with pytest.raises(Crash):
        h.worker.tick()
    started = h.worker.attempts()[0]
    assert started.next_attempt_at == h.clock.utcnow() + timedelta(seconds=5)
    h.clock.advance(120)
    h.restart_worker()
    assert h.worker.attempts()[0].next_attempt_at == started.next_attempt_at
    assert h.worker.tick().accepted == 1


def test_source_disabled_between_queue_and_send_waits_for_enrollment(h, explicit_capabilities):
    h.add()
    h.worker.tick(max_attempts=0)
    h.store.register_source(explicit_capabilities, enabled=False, now=h.clock.utcnow())
    assert h.worker.tick().attempted == 0
    h.store.register_source(explicit_capabilities, enabled=True, now=h.clock.utcnow())
    assert h.worker.tick().accepted == 1


@pytest.mark.parametrize(
    "point,calls,unknown",
    [
        ("attempt_before_commit", 0, False),
        ("attempt_committed", 0, True),
        ("provider_returned", 1, True),
        ("outcome_before_commit", 1, True),
        ("outcome_committed", 1, False),
    ],
)
def test_real_process_exit_boundaries_recover_same_occurrence(h, tmp_path, point, calls, unknown):
    h.add()
    h.worker.tick(max_attempts=0)
    occurrence_id = h.worker.occurrences()[0].occurrence_id
    db_path = h.store.path
    h.store.close()
    receipt_file = tmp_path / "fake-provider-receipt.txt"
    script = """
import os, sys
from datetime import datetime
from pathlib import Path
from decision_mesh.storage import SQLiteStore
from decision_mesh.delivery import DeliveryWorker
from decision_mesh.channels.telegram import TelegramOutcome, TelegramResult
class Clock:
 def utcnow(self): return datetime.fromisoformat(sys.argv[4])
 def monotonic(self): return 0.0
class Channel:
 def send_message(self, chat_id, text):
  Path(sys.argv[2]).write_text('accepted')
  return TelegramResult(TelegramOutcome.ACCEPTED, 'ok', 1)
def crash(point):
 if point == sys.argv[3]: os._exit(73)
with SQLiteStore(sys.argv[1], now=Clock().utcnow()) as store:
 DeliveryWorker(store, Channel(), clock=Clock(), jitter=lambda _: 0, fault_hook=crash).tick()
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(db_path),
            str(receipt_file),
            point,
            h.clock.utcnow().isoformat(),
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 73, result.stderr.decode()
    assert receipt_file.exists() == bool(calls)
    h.store = SQLiteStore(db_path, now=h.clock.utcnow())
    h.restart_worker()
    attempts = h.worker.attempts()
    if unknown:
        assert attempts[0].outcome == "outcome_unknown"
        h.clock.advance(5)
    h.worker.tick()
    assert {r.occurrence_id for r in h.worker.occurrences()} == {occurrence_id}
    assert len(h.channel.calls) == (0 if point == "outcome_committed" else 1)
    assert len(h.worker.attempts()) == (2 if unknown else 1)


@pytest.mark.parametrize("mode,count,first_members", [("immediate", 3, 1), ("digest", 6, 3)])
def test_aging_between_provider_calls_converts_unsent_members_once(h, mode, count, first_members):
    h.settings(delivery_mode=mode, digest_interval_minutes=1)
    records = [h.add(f"boundary-{index}") for index in range(count)]
    source = {r.record_id: h.store.get_record(r.record_id).projection for r in records}
    h.worker.tick(max_attempts=0)
    original = {o.record_id: o for o in h.worker.occurrences()}
    h.clock.advance(3599)

    def advance_first_call():
        if len(h.channel.calls) == 1:
            h.clock.advance(2)

    h.channel.callback = advance_first_call
    h.worker.tick()
    remaining = records[first_members:]
    for record in remaining:
        occurrence = h.worker.occurrences(record.record_id)[0]
        assert occurrence.kind == "historical_summary"
        assert occurrence.occurrence_id == original[record.record_id].occurrence_id
        assert h.worker.attempts(occurrence.occurrence_id) == ()
    assert len(h.channel.calls) == 1
    h.clock.advance(60)
    assert h.worker.tick().accepted == 1
    assert "HISTORICAL" in h.channel.calls[-1][1]
    assert "may already be answered" in h.channel.calls[-1][1]
    assert "Answer in the original chat" not in h.channel.calls[-1][1]
    for record in records:
        occurrence = h.worker.occurrences(record.record_id)[0]
        current = h.store.get_record(record.record_id).projection
        assert occurrence.occurrence_id == original[record.record_id].occurrence_id
        assert len(h.worker.attempts(occurrence.occurrence_id)) == 1
        assert current.aged
        assert current.captured_at == occurrence.captured_at == source[record.record_id].captured_at
        assert current.source_state == source[record.record_id].source_state
        assert current.execution_state == source[record.record_id].execution_state
        assert current.evidence_class == source[record.record_id].evidence_class
    h.restart_worker().tick()
    h.clock.advance(600)
    assert h.worker.tick().attempted == 0
    assert len(h.channel.calls) == 2


@pytest.mark.parametrize("mode", ["immediate", "digest"])
def test_aging_after_durable_start_refreshes_wording_without_resetting_attempt(h, mode):
    h.settings(delivery_mode=mode, digest_interval_minutes=1)
    record = h.add()
    source = h.store.get_record(record.record_id).projection
    h.worker.tick(max_attempts=0)
    occurrence = h.worker.occurrences()[0]
    h.clock.advance(3599)
    start = h.clock.utcnow()

    def advance_at_commit(point):
        if point == "attempt_committed":
            h.clock.advance(2)

    h.worker.fault_hook = advance_at_commit
    assert h.worker.tick().accepted == 1
    body = h.channel.calls[0][1]
    assert "Historical observation; may already be answered" in body
    assert "Answer in the original chat" not in body
    current = h.store.get_record(record.record_id).projection
    assert current.aged
    assert current.source_state == source.source_state
    assert current.execution_state == source.execution_state
    assert current.captured_at == source.captured_at
    final = h.worker.occurrences()[0]
    assert (final.occurrence_id, final.kind, final.part_id) == (
        occurrence.occurrence_id,
        "initial",
        h.worker.attempts()[0].part_id,
    )
    attempt = h.worker.attempts()[0]
    assert attempt.started_at == start
    assert attempt.finished_at == start + timedelta(seconds=2)
    assert not attempt.manual
    assert attempt.outcome == "accepted"
    h.restart_worker().tick()
    h.clock.advance(600)
    assert h.worker.tick().attempted == 0
    assert len(h.channel.calls) == 1


@pytest.mark.parametrize("mode", ["immediate", "digest"])
@pytest.mark.parametrize("prior", ["accepted", "definite_failure", "outcome_unknown"])
@pytest.mark.parametrize("restart", [False, True])
def test_pause_aborted_manual_retry_requires_new_action_and_preserves_budget(
    h, mode, prior, restart
):
    h.settings(delivery_mode=mode, digest_interval_minutes=1)
    record = h.add()
    source = h.store.get_record(record.record_id).projection
    if prior != "accepted":
        outcome = (
            TelegramOutcome.AMBIGUOUS_OUTCOME
            if prior == "outcome_unknown"
            else TelegramOutcome.DEFINITE_FAILURE
        )
        h.channel.results = [failure(outcome) for _ in range(6)]
    h.worker.tick(max_attempts=0)
    h.clock.advance(60)
    h.worker.tick()
    if prior != "accepted":
        for delay in RETRY_SECONDS:
            h.clock.advance(delay)
            h.worker.tick()
    occurrence = h.worker.occurrences()[0]
    prior_attempts = h.worker.attempts()
    automatic_count = 1 if prior == "accepted" else 6
    assert len(prior_attempts) == automatic_count
    h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)

    def pause_at_commit(point):
        if point == "attempt_committed":
            h.settings(global_pause=True)

    h.worker.fault_hook = pause_at_commit
    assert h.worker.tick().accepted == 0
    h.worker.fault_hook = None
    assert len(h.channel.calls) == automatic_count
    aborted = h.worker.attempts()[-1]
    assert aborted.outcome == "not_sent" and aborted.manual
    assert h.worker.attempts()[:-1] == prior_attempts
    h.settings(global_pause=False)
    if restart:
        h.restart_worker()
    h.clock.advance(1000)
    assert h.worker.tick().attempted == 0
    if prior in {"accepted", "outcome_unknown"}:
        with pytest.raises(DeliveryError, match="duplicate_acknowledgement_required"):
            h.worker.manual_retry(occurrence.occurrence_id)
    h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)
    h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)
    h.channel.results = [failure()]
    assert h.worker.tick().attempted == 1
    assert len(h.channel.calls) == automatic_count + 1
    assert h.worker.attempts()[:automatic_count] == prior_attempts
    assert h.worker.attempts()[automatic_count] == aborted
    assert h.worker.attempts()[-1].manual
    with h.store.read_snapshot() as db:
        part = db.execute(
            "SELECT automatic_attempts,manual_pending FROM dm_delivery_parts WHERE part_id=?",
            (occurrence.part_id,),
        ).fetchone()
        assert tuple(part) == (automatic_count, 0)
    h.restart_worker()
    h.clock.advance(1000)
    assert h.worker.tick().attempted == 0
    assert {o.occurrence_id for o in h.worker.occurrences()} == {occurrence.occurrence_id}
    current = h.store.get_record(record.record_id).projection
    assert current.source_state == source.source_state
    assert current.execution_state == source.execution_state
    assert current.captured_at == source.captured_at


@pytest.mark.parametrize("change", ["suppress", "withdraw", "deactivate"])
def test_manual_retry_cancelled_at_commit_cannot_be_reauthorized(h, change):
    record = h.add()
    h.worker.tick()
    occurrence = h.worker.occurrences()[0]
    h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)

    def cancel_at_commit(point):
        if point != "attempt_committed":
            return
        if change == "suppress":
            h.store.set_record_metadata(record.record_id, suppressed=True, now=h.clock.utcnow())
        elif change == "withdraw":
            h.add(revision=2, event_kind="request.withdrawn", outcome="withdrawn")
        else:
            h.settings(channel_active=False)

    h.worker.fault_hook = cancel_at_commit
    assert h.worker.tick().accepted == 0
    expected_source = h.store.get_record(record.record_id).projection
    h.restart_worker().tick()
    with pytest.raises(DeliveryError, match="occurrence_not_eligible"):
        h.worker.manual_retry(occurrence.occurrence_id, acknowledge_duplicate=True)
    assert len(h.channel.calls) == 1
    assert [a.outcome for a in h.worker.attempts()] == ["accepted", "not_sent"]
    assert h.worker.occurrences()[0].state == "cancelled"
    assert h.store.get_record(record.record_id).projection == expected_source
