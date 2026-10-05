"""Delivery summaries distinguish durable acceptance, ambiguity and pending work."""

import pytest
from test_delivery import failure
from test_delivery import h as h  # noqa: PLC0414 - shared pytest fixture, explicitly re-exported.

from decision_mesh.channels.telegram import TelegramOutcome
from decision_mesh.delivery import DeliveryError, DeliveryWorker
from decision_mesh.storage import SQLiteStore


def test_delivery_pages_use_durable_evidence_not_unbounded_readers(h, monkeypatch):
    first = h.add("first")
    second = h.add("second")
    assert h.worker.occurrence_page().total == 0  # GET must not create occurrences.
    h.worker.tick(max_attempts=1)
    original = h.worker.occurrences()
    monkeypatch.setattr(h.worker, "occurrences", lambda *args: pytest.fail("unbounded occurrences"))
    monkeypatch.setattr(h.worker, "attempts", lambda *args: pytest.fail("unbounded attempts"))
    monkeypatch.setattr(h.store, "get_record", lambda *args: pytest.fail("request hydration"))
    changes = h.store._db.total_changes
    page = h.worker.occurrence_page(limit=1)
    assert page.total == 2 and len(page.occurrences) == 1 and page.next_cursor
    assert page.last_api_acceptance_at == h.clock.utcnow()
    accepted = page.occurrences[0]
    assert accepted.record_id == first.record_id
    assert accepted.short_reference == first.short_reference
    assert accepted.status == "accepted" and accepted.attempts == 1
    assert accepted.duplicate_possible and accepted.retry_available
    assert accepted.last_api_acceptance_at == h.clock.utcnow()
    second_page = h.worker.occurrence_page(cursor=page.next_cursor, limit=1)
    queued = second_page.occurrences[0]
    assert queued.record_id == second.record_id and queued.status == "queued"
    assert queued.attempts == 0 and not queued.duplicate_possible and not queued.retry_available
    assert queued.last_api_acceptance_at is None
    assert second_page.next_cursor is None and second_page.total == 2
    assert len(original) == 2 and h.store._db.total_changes == changes


def test_ambiguous_retry_exhaustion_and_manual_pending_flags(h):
    h.channel.results = [failure(TelegramOutcome.AMBIGUOUS_OUTCOME)] * 6
    receipt = h.add()
    for seconds in [0, 5, 15, 60, 300, 900]:
        h.clock.advance(seconds)
        h.worker.tick(max_attempts=1)
    row = h.worker.occurrence_page(record_id=receipt.record_id).occurrences[0]
    assert row.status == "outcome_unknown" and row.attempts == 6
    assert row.duplicate_possible and row.retry_available
    assert row.last_api_acceptance_at is None
    h.worker.manual_retry(row.occurrence_id, acknowledge_duplicate=True)
    pending = h.worker.occurrence_page().occurrences[0]
    assert pending.status == "queued" and not pending.retry_available
    assert pending.attempts == 6 and pending.duplicate_possible
    h.worker.tick(max_attempts=1)
    accepted = h.worker.occurrence_page().occurrences[0]
    assert accepted.status == "accepted" and accepted.attempts == 7
    assert accepted.last_api_acceptance_at == h.clock.utcnow()


def test_digest_manual_target_attempt_count_does_not_attribute_peer_retry(h):
    h.settings(delivery_mode="digest")
    h.add("first")
    h.add("second")
    h.worker.tick()
    h.clock.advance(601)
    h.worker.tick()
    rows = h.worker.occurrence_page().occurrences
    assert len(rows) == 2 and all(row.attempts == 1 for row in rows)
    h.worker.manual_retry(rows[0].occurrence_id, acknowledge_duplicate=True)
    pending_rows = h.worker.occurrence_page().occurrences
    assert [row.status for row in pending_rows] == ["queued", "accepted"]
    assert not any(row.retry_available for row in pending_rows)
    h.worker.tick()
    rows_after = h.worker.occurrence_page().occurrences
    assert [row.attempts for row in rows_after] == [2, 1]


def test_offline_summary_absent_extension_and_no_crash_recovery(tmp_path, now, h):
    with SQLiteStore(tmp_path / "empty" / "mesh.db", now=now) as bare:
        assert DeliveryWorker.inspect_summary(bare.path).total == 0
        assert DeliveryWorker.inspect_summary(bare.path).last_api_acceptance_at is None
    h.add()
    h.worker.tick()
    before = h.worker.attempts()
    changes = h.store._db.total_changes
    result = DeliveryWorker.inspect_summary(h.store.path)
    assert result.total == 1 and result.last_api_acceptance_at == h.clock.utcnow()
    assert h.worker.attempts() == before and h.store._db.total_changes == changes


@pytest.mark.parametrize("limit", [0, -1, 101, True, "10", None])
def test_delivery_strict_limits(h, limit):
    with pytest.raises(DeliveryError, match="^invalid_query_limit$"):
        h.worker.occurrence_page(limit=limit)


def test_delivery_cursor_and_record_validation_redacted(h):
    h.add("first")
    h.add("second")
    h.worker.tick()
    cursor = h.worker.occurrence_page(limit=1).next_cursor
    for bad in ["SECRET SQL", "x" * 1025, True, {}, ""]:
        with pytest.raises(DeliveryError, match="^invalid_query_cursor$"):
            h.worker.occurrence_page(cursor=bad)
    with pytest.raises(DeliveryError, match="invalid_query_cursor"):
        h.worker.occurrence_page(cursor=cursor, record_id="different")
    for bad in ["", True, "x" * 257, "PRIVATE\x00"]:
        with pytest.raises(DeliveryError, match="^invalid_record_id$"):
            h.worker.occurrence_page(record_id=bad)


def test_large_retained_delivery_history_does_not_load_bodies_or_attempt_rows(h, monkeypatch):
    receipt = h.add()
    h.worker.tick()
    template = h.worker.occurrences()[0]
    with h.store.transaction() as db:
        original = dict(db.execute("SELECT * FROM dm_delivery_occurrences").fetchone())
        columns = tuple(original)
        sql = (
            "INSERT INTO dm_delivery_occurrences("
            + ",".join(columns)
            + ") VALUES ("
            + ",".join("?" for _ in columns)
            + ")"
        )
        db.executemany(
            sql,
            (
                tuple(
                    (original | {"occurrence_id": f"occ-{i}", "revision": i + 2})[c]
                    for c in columns
                )
                for i in range(20_000)
            ),
        )
    monkeypatch.setattr(h.worker, "occurrences", lambda *args: pytest.fail("unbounded occurrences"))
    monkeypatch.setattr(h.worker, "attempts", lambda *args: pytest.fail("unbounded attempts"))
    monkeypatch.setattr(h.store, "get_record", lambda *args: pytest.fail("body loaded"))
    page = h.worker.occurrence_page(limit=2)
    assert page.total == 20_001 and len(page.occurrences) == 2 and page.next_cursor
    assert page.occurrences[0].occurrence_id == template.occurrence_id
    assert page.occurrences[0].short_reference == receipt.short_reference
    assert page.occurrences[1].attempts == 0


def test_readers_preserve_interrupted_attempt_without_claiming_acceptance(h):
    h.add()

    def interrupt(point):
        if point == "attempt_committed":
            raise RuntimeError("synthetic process interruption")

    h.worker.fault_hook = interrupt
    with pytest.raises(RuntimeError):
        h.worker.tick()
    before = h.worker.attempts()
    assert before[0].outcome == "started"
    summary = DeliveryWorker.inspect_summary(h.store.path)
    row = h.worker.occurrence_page().occurrences[0]
    assert summary.last_api_acceptance_at is None
    assert row.status == "inflight" and row.attempts == 1 and row.duplicate_possible
    assert not row.retry_available and row.last_api_acceptance_at is None
    assert h.worker.attempts() == before and not h.channel.calls


def test_delivery_summary_excludes_private_projection_and_provider_details(h):
    h.add(snapshot_changes={"title": "PRIVATE_TITLE", "summary": "PRIVATE_SUMMARY"})
    h.worker.tick()
    with h.store.transaction() as db:
        db.execute("UPDATE dm_delivery_occurrences SET reason='PRIVATE_REASON'")
        db.execute("UPDATE dm_delivery_attempts SET provider_message_id=987654321")
    page = h.worker.occurrence_page()
    assert "PRIVATE" not in repr(page) and "987654321" not in repr(page)


def test_offline_delivery_missing_database_not_created(tmp_path):
    path = tmp_path / "PRIVATE-missing.db"
    with pytest.raises(DeliveryError, match="^database_inspection_failed$"):
        DeliveryWorker.inspect_summary(path)
    assert not path.exists()


@pytest.mark.parametrize("record_id", [chr(0xD800), chr(0xDFFF), "PRIVATE" + chr(0xD800)])
def test_qry2_surrogate_delivery_filter_has_fixed_error_before_database(h, monkeypatch, record_id):
    monkeypatch.setattr(
        h.store, "read_snapshot", lambda: pytest.fail("invalid filter reached SQLite")
    )
    with pytest.raises(DeliveryError, match="^invalid_record_id$"):
        h.worker.occurrence_page(record_id=record_id)
