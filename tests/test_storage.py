"""Real transactions, process crashes, replay, privacy and conservative restore."""

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest

from decision_mesh.capture import atomic_write_owner_only
from decision_mesh.contracts import ConnectionState, SourceState, canonical_event_bytes
from decision_mesh.domain import MeshState, reduce_event
from decision_mesh.settings import DestinationIdentity, SettingsConflict, SettingsError
from decision_mesh.storage import CapacityError, SQLiteStore, StorageError


@pytest.fixture
def store(tmp_path, now, explicit_capabilities):
    with SQLiteStore(tmp_path / "data" / "mesh.db", now=now) as value:
        value.register_source(explicit_capabilities)
        yield value


def activate(store, now):
    store.update_settings(
        store.get_settings().revision,
        {
            "channel_active": True,
            "destination": DestinationIdentity(chat_id=123, bot_id=456),
        },
        now=now,
    )
    return store.current_policy().policy_ref


def counts(store):
    with store.read_snapshot() as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("events", "records", "eligibility", "revisions")
        )


def test_real_wal_full_and_single_writer(store):
    with store.read_snapshot() as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    with store.transaction() as db:
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 2
    with pytest.raises(StorageError):
        SQLiteStore(store.path, busy_timeout_ms=0)


def test_read_snapshot_survives_writer_commit(store, event_factory, now):
    with store.read_snapshot() as snapshot:
        assert snapshot.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        store.ingest(event_factory(), received_at=now)
        assert snapshot.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert counts(store)[0] == 1


@pytest.mark.parametrize("boundary", ["event_written", "projection_written", "eligibility_written"])
def test_injected_failure_rolls_back_whole_ingestion(store, event_factory, now, boundary):
    def fail(point):
        if point == boundary:
            raise RuntimeError("synthetic interruption")

    store._fault_hook = fail
    with pytest.raises(RuntimeError):
        store.ingest(event_factory(), received_at=now)
    assert counts(store) == (0, 0, 0, 0)
    store._fault_hook = None
    assert store.ingest(event_factory(), received_at=now).sequence == 1


def test_replay_reopen_returns_original_stable_receipt(
    tmp_path, explicit_capabilities, event_factory, now
):
    path = tmp_path / "data" / "mesh.db"
    event = event_factory()
    with SQLiteStore(path, now=now) as first:
        first.register_source(explicit_capabilities)
        receipt = first.ingest(event, received_at=now)
    with SQLiteStore(path, now=now + timedelta(minutes=1)) as reopened:
        replay = reopened.ingest(event, received_at=now + timedelta(minutes=1))
        assert replace(replay, replayed=False) == receipt
        assert replay.replayed
        assert counts(reopened) == (1, 1, 1, 1)
        assert reopened.lookup_reference(receipt.short_reference).projection.key == (
            "agent-local",
            "question-1",
        )


@pytest.mark.parametrize(
    "boundary,committed",
    [
        ("event_written", False),
        ("projection_written", False),
        ("eligibility_written", False),
        ("committed", True),
    ],
)
def test_real_process_exit_transaction_boundaries(
    tmp_path, now, explicit_capabilities, event_factory, boundary, committed
):
    path = tmp_path / "data" / "mesh.db"
    event = event_factory()
    with SQLiteStore(path, now=now) as setup:
        setup.register_source(explicit_capabilities)
    script = """
import os, sys
from datetime import datetime
from decision_mesh.storage import SQLiteStore
point = sys.argv[2]
def crash(current):
    if current == point:
        os._exit(79)
with SQLiteStore(sys.argv[1], now=datetime.fromisoformat(sys.argv[3]), fault_hook=crash) as store:
    store.ingest(sys.stdin.buffer.read(), received_at=datetime.fromisoformat(sys.argv[3]))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), boundary, now.isoformat()],
        input=canonical_event_bytes(event),
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 79, result.stderr.decode()
    with SQLiteStore(path, now=now) as reopened:
        assert counts(reopened) == ((1, 1, 1, 1) if committed else (0, 0, 0, 0))
        receipt = reopened.ingest(event, received_at=now)
        assert receipt.replayed == committed
        assert counts(reopened) == (1, 1, 1, 1)


def test_event_revision_conflict_and_stale_do_not_overwrite(store, event_factory, now):
    first = store.ingest(event_factory(), received_at=now)
    conflict = store.ingest(
        event_factory(snapshot_changes={"title": "SECRET-conflict"}), received_at=now
    )
    assert conflict.category == "conflict"
    revision = store.ingest(
        event_factory(event_id="other", snapshot_changes={"title": "wrong"}), received_at=now
    )
    assert revision.category == "conflict"
    store.ingest(
        event_factory(
            event_kind="request.updated", revision=3, snapshot_changes={"title": "latest"}
        ),
        received_at=now,
    )
    lower = store.ingest(
        event_factory(
            event_kind="request.updated", revision=2, snapshot_changes={"title": "stale"}
        ),
        received_at=now,
    )
    assert lower.category == "stale"
    assert store.get_record(first.record_id).projection.snapshot.title == "latest"


def test_registration_never_trusts_event_and_namespace_is_enforced(
    store, native_capabilities, event_factory, now
):
    with pytest.raises(StorageError, match="namespace"):
        store.ingest(event_factory(), received_at=now, expected_producer_id="different")
    with pytest.raises(StorageError, match="enrolled"):
        store.ingest(event_factory(producer_id="stranger"), received_at=now)
    store.register_source(native_capabilities)
    assert not store.source_registration("codex-native")["enabled"]
    assert not store.source_registration("codex-native")["qualified"]
    with pytest.raises(StorageError, match="unverified"):
        store.register_source(native_capabilities, enabled=True)
    with pytest.raises(StorageError, match="disabled"):
        store.ingest(event_factory(native=True), received_at=now)


def test_redacted_validation_errors(store, now):
    with pytest.raises(StorageError) as error:
        store.ingest({"secret": "DO-NOT-ECHO-SECRET"}, received_at=now)
    assert "SECRET" not in str(error.value)
    assert error.value.__suppress_context__
    assert counts(store)[0] == 0


def test_native_confirmation_lost_on_restart(tmp_path, native_capabilities, event_factory, now):
    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as first:
        first.register_source(native_capabilities, enabled=True, qualified=True)
        receipt = first.ingest(
            event_factory(native=True, current=True, restored=True), received_at=now
        )
        before = first.get_record(receipt.record_id).projection
        assert before.current_confirmed
    with SQLiteStore(path, now=now + timedelta(seconds=5)) as reopened:
        after = reopened.get_record(receipt.record_id).projection
        assert not after.current_confirmed and after.last_known_pending
        assert after.last_confirmed_at == before.last_confirmed_at
        assert after.source_context == before.source_context


def test_native_source_gap_demotes_other_records(store, native_capabilities, event_factory, now):
    store.register_source(native_capabilities, enabled=True, qualified=True)
    first = store.ingest(event_factory(native=True, current=True, restored=True), received_at=now)
    store.ingest(
        event_factory(native=True, request_id="second", revision=4, event_id="gap"), received_at=now
    )
    assert not store.get_record(first.record_id).projection.current_confirmed


def test_policy_generation_blocks_old_spool_and_pause_retains_it(store, event_factory, now):
    policy = activate(store, now)
    store.update_settings(1, {"global_pause": True}, now=now)
    first = store.ingest(event_factory(capture_policy_ref=policy), received_at=now)
    assert store.eligibility_after()[0].kind == "candidate"
    store.update_settings(2, {"channel_active": False}, now=now)
    store.update_settings(3, {"channel_active": True}, now=now)
    store.ingest(
        event_factory(request_id="second", event_id="second", capture_policy_ref=policy),
        received_at=now,
    )
    rows = store.eligibility_after()
    assert rows[0].kind == "cancelled"
    assert rows[1].kind == "local_only"
    assert store.get_record(first.record_id).projection.source_state == SourceState.UNVERIFIED


def test_delayed_capture_preserves_age_and_only_historical_policy_eligibility(
    store, event_factory, now
):
    policy = activate(store, now)
    event = event_factory(capture_policy_ref=policy)
    receipt = store.ingest(event, received_at=now + timedelta(minutes=70))
    record = store.get_record(receipt.record_id).projection
    assert record.captured_at == now and record.aged
    assert record.aging_deadline == now + timedelta(minutes=60)
    assert store.eligibility_after()[0].kind == "historical_summary"


def test_metadata_independent_source_state(store, event_factory, now):
    policy = activate(store, now)
    receipt = store.ingest(event_factory(capture_policy_ref=policy), received_at=now)
    before = store.get_record(receipt.record_id).projection
    store.set_record_metadata(
        receipt.record_id, seen=True, snoozed_until=now + timedelta(minutes=10), now=now
    )
    after = store.get_record(receipt.record_id)
    assert after.projection == before and after.seen
    assert store.eligibility_after()[0].kind == "candidate"
    store.set_record_metadata(receipt.record_id, suppressed=True, now=now)
    assert store.eligibility_after()[0].kind == "cancelled"
    assert store.get_record(receipt.record_id).projection == before


def test_pruning_keeps_tombstones_and_shortrefs_and_prevents_resurrection(
    tmp_path, explicit_capabilities, event_factory, now
):
    with SQLiteStore(tmp_path / "data" / "mesh.db", detail_limit=1, now=now) as store:
        store.register_source(explicit_capabilities)
        first = store.ingest(event_factory(), received_at=now)
        store.ingest(
            event_factory(event_kind="request.resolved", revision=2, outcome="resolved"),
            received_at=now,
        )
        store.ingest(event_factory(request_id="second", event_id="second"), received_at=now)
        tombstone = store.lookup_reference(first.short_reference)
        assert not tombstone.detail_retained and tombstone.projection.terminal
        assert tombstone.projection.snapshot is None
        replay = store.ingest(event_factory(), received_at=now)
        assert replay.replayed and replay.short_reference == first.short_reference
        reopen = store.ingest(event_factory(revision=3), received_at=now)
        assert reopen.category == "conflict"
        assert store.get_record(first.record_id).projection.terminal


def test_capacity_refuses_new_active_without_losing_committed_record(
    tmp_path, explicit_capabilities, event_factory, now
):
    with SQLiteStore(tmp_path / "data" / "mesh.db", detail_limit=1, now=now) as store:
        store.register_source(explicit_capabilities)
        first = store.ingest(event_factory(), received_at=now)
        with pytest.raises(CapacityError):
            store.ingest(event_factory(request_id="second", event_id="second"), received_at=now)
        assert counts(store) == (1, 1, 1, 1)
        assert store.get_record(first.record_id).detail_retained


def test_shortref_collision_regenerates_including_tombstones(
    tmp_path, explicit_capabilities, event_factory, now
):
    references = iter(["ABCDEFGH", "ABCDEFGH", "JKLMNPQR"])
    with SQLiteStore(
        tmp_path / "data" / "mesh.db",
        detail_limit=1,
        now=now,
        reference_factory=lambda: next(references),
    ) as store:
        store.register_source(explicit_capabilities)
        first = store.ingest(event_factory(), received_at=now)
        store.age_records(now=now + timedelta(hours=1))
        second = store.ingest(
            event_factory(request_id="two", event_id="two", captured_at=now + timedelta(hours=1)),
            received_at=now + timedelta(hours=1),
        )
        assert first.short_reference == "ABCDEFGH" and second.short_reference == "JKLMNPQR"


def test_aliases_normalized_persisted_and_never_rename_implicitly(store):
    alias = store.project_alias(None, local_path="D:\\Projects\\Example")
    store.rename_alias(alias.identity, "Work")
    same = store.project_alias(None, local_path="d:/projects/EXAMPLE/.")
    assert same.alias == "Work"
    assert same.local_path == alias.local_path
    assert store.project_alias("adapter-stable", local_path="D:/renamed").alias == "Project 2"
    assert store.project_alias(None).alias == "Unknown project"


def test_extension_migration_rollback_and_schema_refusal(store):
    with pytest.raises(StorageError):
        store.install_extension(
            "delivery", 1, ("CREATE TABLE delivery_test (id INTEGER)", "INVALID SQL")
        )
    with store.read_snapshot() as db:
        assert (
            db.execute("SELECT 1 FROM sqlite_master WHERE name='delivery_test'").fetchone() is None
        )
        assert db.execute("SELECT 1 FROM extensions").fetchone() is None
    store.install_extension("delivery", 1, ("CREATE TABLE delivery_test (id INTEGER)",))
    store.install_extension("delivery", 1, ("INVALID SQL",))
    with pytest.raises(StorageError, match="gap"):
        store.install_extension("delivery", 3, ())


def test_corrupt_and_newer_schema_refusal(tmp_path, now):
    corrupt = tmp_path / "corrupt" / "mesh.db"
    atomic_write_owner_only(corrupt, b"not a database")
    with pytest.raises(StorageError):
        SQLiteStore(corrupt, now=now)
    newer = tmp_path / "newer" / "mesh.db"
    with SQLiteStore(newer, now=now) as store, store.transaction() as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(StorageError, match="newer_schema"):
        SQLiteStore(newer, now=now)


def test_backup_restore_epoch_history_and_old_missing_spool_is_audit_only(
    store, event_factory, now, tmp_path
):
    policy = activate(store, now)
    first = store.ingest(event_factory(capture_policy_ref=policy), received_at=now)
    backup = store.backup(tmp_path / "backup" / "mesh.db")
    with SQLiteStore.restore_backup(
        backup, tmp_path / "restored" / "mesh.db", now=now + timedelta(minutes=1)
    ) as restored:
        record = restored.get_record(first.record_id)
        assert record.restored and record.projection.visibility == "history"
        assert record.projection.source_state == SourceState.UNVERIFIED
        assert restored.eligibility_after()[0].kind == "restore_suppressed"
        assert not restored.get_settings().channel_active
        assert (
            restored.current_policy().destination_generation
            > store.current_policy().destination_generation
        )
        missing = restored.ingest(
            event_factory(request_id="missing", event_id="missing", capture_policy_ref=policy),
            received_at=now + timedelta(minutes=2),
        )
        assert "pre_restore_audit_only" in missing.flags
        assert missing.record_id is None
        assert restored.eligibility_after()[-1].kind == "audit_only"
        assert len(restored.list_records()) == 1


def test_separate_execution_revision_durable(store, native_capabilities, event_factory, now):
    store.register_source(native_capabilities, enabled=True, qualified=True)
    receipt = store.ingest(event_factory(native=True, revision=4), received_at=now)
    store.ingest(
        event_factory(native=True, event_kind="execution.updated", revision=1), received_at=now
    )
    projection = store.get_record(receipt.record_id).projection
    assert projection.request_revision == 4 and projection.execution_revision == 1


def test_bounded_event_detail_without_full_history_replay(store, event_factory, now):
    store.detail_limit = 3
    for revision in range(1, 10):
        store.ingest(
            event_factory(revision=revision, snapshot_changes={"title": f"Revision {revision}"}),
            received_at=now,
        )
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 9
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 9
        assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 3
    assert store.ingest(event_factory(), received_at=now).category == "conflict"


def test_retention_expiry_preserves_scope_provenance(store, event_factory, now):
    event = event_factory(context_changes={"session_id": "one-session"})
    receipt = store.ingest(event, received_at=now)
    store.age_records(now=now + timedelta(hours=1))
    store.age_records(now=now + timedelta(days=31))
    record = store.get_record(receipt.record_id)
    assert not record.detail_retained
    assert record.projection.source_context == event.source_context
    assert record.projection.source_state == SourceState.UNVERIFIED
    assert record.short_reference == receipt.short_reference


def test_suppression_cannot_be_undone_by_new_material_event(store, event_factory, now):
    policy = activate(store, now)
    receipt = store.ingest(event_factory(capture_policy_ref=policy), received_at=now)
    store.set_record_metadata(receipt.record_id, suppressed=True, now=now)
    store.ingest(
        event_factory(
            revision=2, capture_policy_ref=policy, snapshot_changes={"title": "Material change"}
        ),
        received_at=now,
    )
    assert all(item.kind == "cancelled" for item in store.eligibility_after())


def test_restart_cannot_lower_future_health_barrier(
    tmp_path, native_capabilities, event_factory, now
):
    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        future = now + timedelta(minutes=3)
        store.ingest(
            event_factory(
                native=True,
                event_kind="source.health",
                captured_at=future,
                payload_changes={"connection_state": "disconnected"},
            ),
            received_at=now,
        )
    with SQLiteStore(path, now=now + timedelta(minutes=1)) as reopened:
        receipt = reopened.ingest(
            event_factory(
                native=True, current=True, restored=True, captured_at=now + timedelta(minutes=2)
            ),
            received_at=now + timedelta(minutes=2),
        )
        assert not reopened.get_record(receipt.record_id).projection.current_confirmed


def test_session_end_persists_before_any_record_and_bounds_identity_lookup(
    tmp_path, native_capabilities, event_factory, now
):
    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        store.ingest(
            event_factory(
                native=True,
                event_kind="source.health",
                captured_at=now + timedelta(minutes=2),
                context_changes={"session_id": "ended"},
                payload_changes={"session_ended": True},
            ),
            received_at=now + timedelta(minutes=2),
        )
    with SQLiteStore(path, now=now + timedelta(minutes=3)) as reopened:
        late = reopened.ingest(
            event_factory(
                native=True,
                event_kind="observation.recorded",
                evidence_class="prompt_confirmed",
                context_changes={"session_id": "ended"},
            ),
            received_at=now + timedelta(minutes=3),
        )
        assert reopened.get_record(late.record_id).projection.aged
        other = reopened.ingest(
            event_factory(
                native=True,
                event_kind="observation.recorded",
                event_id="other-session",
                evidence_class="prompt_confirmed",
                context_changes={"session_id": "other"},
            ),
            received_at=now + timedelta(minutes=3),
        )
        assert not reopened.get_record(other.record_id).projection.aged


def test_failed_schema_migration_restores_previous_schema(tmp_path, now, monkeypatch):
    from decision_mesh import storage

    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now):
        pass
    previous_version = storage.SCHEMA_VERSION
    target_version = previous_version + 1
    monkeypatch.setattr(storage, "SCHEMA_VERSION", target_version)
    monkeypatch.setitem(
        storage.MIGRATIONS,
        target_version,
        ("CREATE TABLE transient_migration (id INTEGER)", "INVALID SQL"),
    )
    with pytest.raises(StorageError):
        SQLiteStore(path, now=now)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == previous_version
        assert (
            db.execute("SELECT 1 FROM sqlite_master WHERE name='transient_migration'").fetchone()
            is None
        )
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    backups = list(path.parent.glob(f"*.pre-v{target_version}-*.bak"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    monkeypatch.setattr(storage, "SCHEMA_VERSION", previous_version)
    with SQLiteStore(path, now=now):
        pass


def test_failed_restore_is_never_published_as_normal_database(store, event_factory, now, tmp_path):
    store.ingest(event_factory(), received_at=now)
    backup = store.backup(tmp_path / "backup" / "mesh.db")
    destination = tmp_path / "restored" / "mesh.db"

    def fail(point):
        if point == "restore_applied":
            raise RuntimeError("synthetic restore interruption")

    with pytest.raises(RuntimeError):
        SQLiteStore.restore_backup(backup, destination, now=now, fault_hook=fail)
    assert not destination.exists()
    assert store.list_records()[0].projection.visibility == "active"


def test_real_restore_crash_never_publishes_unsafe_copy(store, event_factory, now, tmp_path):
    store.ingest(event_factory(), received_at=now)
    backup = store.backup(tmp_path / "backup" / "mesh.db")
    destination = tmp_path / "restored" / "mesh.db"
    script = """
import os, sys
from datetime import datetime
from decision_mesh.storage import SQLiteStore
def crash(point):
    if point == 'restore_applied':
        os._exit(82)
SQLiteStore.restore_backup(sys.argv[1], sys.argv[2], now=datetime.fromisoformat(sys.argv[3]), fault_hook=crash)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(backup), str(destination), now.isoformat()],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 82, result.stderr.decode()
    assert not destination.exists()


def test_restored_native_pending_and_epoch_require_fresh_reconciliation(
    store, native_capabilities, event_factory, now, tmp_path
):
    store.register_source(native_capabilities, enabled=True, qualified=True)
    receipt = store.ingest(event_factory(native=True, current=True, restored=True), received_at=now)
    backup = store.backup(tmp_path / "backup" / "mesh.db")
    with SQLiteStore.restore_backup(
        backup, tmp_path / "restored" / "mesh.db", now=now + timedelta(seconds=1)
    ) as restored:
        projection = restored.get_record(receipt.record_id).projection
        assert projection.last_known_pending and not projection.current_confirmed
        assert projection.last_confirmed_at == now
        assert restored.recovery_state().epoch != store.recovery_state().epoch
        assert restored.recovery_state().restored_at == now + timedelta(seconds=1)


def test_bounded_slice_does_not_load_historical_event_log(store, event_factory, now, monkeypatch):
    from decision_mesh import storage

    for revision in range(1, 40):
        store.ingest(event_factory(revision=revision), received_at=now)
    original = storage.reduce_event

    def bounded(state, event, **kwargs):
        assert len(state.records) <= 1
        assert len(state.events) <= 1
        assert len(state.revisions) <= 1
        assert state.audit == ()
        return original(state, event, **kwargs)

    monkeypatch.setattr(storage, "reduce_event", bounded)
    store.ingest(event_factory(revision=40), received_at=now)


def test_pruned_snapshot_digest_preserves_non_substantive_age_and_policy(store, event_factory, now):
    policy = activate(store, now)
    first = store.ingest(event_factory(capture_policy_ref=policy), received_at=now)
    store.age_records(now=now + timedelta(hours=1))
    later = now + timedelta(days=31)
    store.age_records(now=later)
    compact = store.get_record(first.record_id)
    assert not compact.detail_retained and compact.projection.snapshot_digest
    original_digest = compact.projection.snapshot_digest
    store.update_settings(1, {"disclosure_fields": ["action"]}, now=later)
    new_policy = store.current_policy().policy_ref
    repeated = store.ingest(
        event_factory(revision=2, captured_at=later, capture_policy_ref=new_policy),
        received_at=later,
    )
    assert "non_substantive_revision" in repeated.flags
    same = store.get_record(first.record_id).projection
    assert same.aged and same.visibility == "history"
    assert same.captured_at == now and same.capture_policy_ref == policy
    assert same.snapshot_digest == original_digest
    assert len(store.eligibility_after()) == 1
    changed = store.ingest(
        event_factory(
            revision=3,
            captured_at=later,
            capture_policy_ref=new_policy,
            snapshot_changes={"title": "New evidence"},
        ),
        received_at=later,
    )
    assert "non_substantive_revision" not in changed.flags
    fresh = store.get_record(first.record_id).projection
    assert not fresh.aged and fresh.captured_at == later
    assert fresh.capture_policy_ref == new_policy
    assert fresh.snapshot_digest != original_digest


def test_confirmed_active_never_pruned_under_capacity_pressure(
    tmp_path, native_capabilities, event_factory, now
):
    with SQLiteStore(tmp_path / "data" / "mesh.db", detail_limit=1, now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        first = store.ingest(
            event_factory(native=True, current=True, restored=True), received_at=now
        )
        with pytest.raises(CapacityError):
            store.ingest(
                event_factory(
                    native=True, event_id="second", request_id="second", current=True, restored=True
                ),
                received_at=now,
            )
        assert store.get_record(first.record_id).projection.current_confirmed
        assert store.get_record(first.record_id).detail_retained


@pytest.mark.parametrize("loss", ["health", "gap", "registration", "restart"])
def test_snapshotless_execution_keeps_known_loss_until_exact_reconciliation(
    tmp_path, native_capabilities, event_factory, now, loss
):
    path = tmp_path / "data" / "mesh.db"
    store = SQLiteStore(path, now=now)
    state = MeshState()

    def ingest(event):
        nonlocal state
        state = reduce_event(
            state, event, received_at=event.captured_at, capabilities=native_capabilities
        ).state
        return store.ingest(event, received_at=event.captured_at)

    try:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        ingest(event_factory(native=True, event_kind="source.health", event_id="online"))
        first = ingest(event_factory(native=True, event_kind="execution.updated"))
        assert store.get_record(first.record_id).projection.snapshot is None
        assert not store.get_record(first.record_id).detail_retained
        lost_at = now + timedelta(seconds=1)
        if loss == "health":
            ingest(
                event_factory(
                    native=True,
                    event_kind="source.health",
                    event_id="offline",
                    captured_at=lost_at,
                    payload_changes={"connection_state": "disconnected"},
                )
            )
        elif loss == "gap":
            ingest(
                event_factory(
                    native=True,
                    request_id="other",
                    event_id="gap",
                    revision=4,
                    captured_at=lost_at,
                )
            )
        elif loss == "registration":
            store.register_source(native_capabilities, enabled=False, qualified=True, now=lost_at)
            store.register_source(native_capabilities, enabled=True, qualified=True, now=lost_at)
        else:
            store.close()
            store = SQLiteStore(path, now=lost_at)
        disconnected = store.get_record(first.record_id).projection
        expected = ConnectionState.GAPPED if loss == "gap" else ConnectionState.DISCONNECTED
        assert disconnected.connection_state == expected
        ordinary = ingest(
            event_factory(native=True, event_id="opened", captured_at=now + timedelta(seconds=2))
        )
        projected = store.get_record(ordinary.record_id).projection
        assert not projected.current_confirmed and projected.last_known_pending
        assert projected.connection_state == expected
        assert store.eligibility_after()[-1].kind == "local_only"
        if loss in {"health", "gap"}:
            assert projected == state.record(projected.key)
        # Neither repeated online health nor ordinary request evidence qualifies
        # recovery. A fresh exact native snapshot still can.
        ingest(
            event_factory(
                native=True,
                event_kind="source.health",
                event_id="online-again",
                captured_at=now + timedelta(seconds=3),
            )
        )
        ingest(
            event_factory(
                native=True,
                event_id="ordinary-update",
                revision=2,
                captured_at=now + timedelta(seconds=4),
            )
        )
        assert not store.get_record(first.record_id).projection.current_confirmed
        ingest(
            event_factory(
                native=True,
                event_id="reconciled",
                revision=3,
                current=True,
                restored=True,
                captured_at=now + timedelta(seconds=5),
            )
        )
        confirmed = store.get_record(first.record_id).projection
        assert confirmed.current_confirmed
        assert confirmed.last_confirmed_at == now + timedelta(seconds=5)
        assert confirmed.connection_state == ConnectionState.CONTINUOUS
    finally:
        store.close()


def test_live_orphans_are_bounded_but_pruned_identities_do_not_fill_slices(
    tmp_path, native_capabilities, event_factory, now, monkeypatch
):
    from decision_mesh import storage

    with SQLiteStore(tmp_path / "data" / "mesh.db", detail_limit=2, now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        for number in range(10):
            store.ingest(
                event_factory(
                    native=True,
                    request_id=f"history-{number}",
                    event_id=f"history-{number}",
                    event_kind="request.resolved",
                    outcome="answered",
                ),
                received_at=now,
            )
        store.age_records(now=now + timedelta(days=31))
        store.register_source(native_capabilities, enabled=True, qualified=True)
        first = store.ingest(
            event_factory(native=True, event_kind="execution.updated"), received_at=now
        )
        store.ingest(
            event_factory(
                native=True,
                event_kind="execution.updated",
                request_id="other",
                event_id="other",
            ),
            received_at=now,
        )
        before = counts(store)
        with pytest.raises(CapacityError):
            store.ingest(
                event_factory(
                    native=True,
                    event_kind="execution.updated",
                    request_id="excess",
                    event_id="excess",
                ),
                received_at=now,
            )
        assert counts(store) == before
        original = storage.reduce_event

        def bounded(state, event, **kwargs):
            assert len(state.records) == 2
            assert all(record.snapshot is None for record in state.records)
            return original(state, event, **kwargs)

        monkeypatch.setattr(storage, "reduce_event", bounded)
        store.ingest(
            event_factory(
                native=True,
                event_kind="source.health",
                event_id="loss",
                payload_changes={"connection_state": "disconnected"},
            ),
            received_at=now,
        )
        assert store.get_record(first.record_id).projection.connection_state == "disconnected"
        assert len(store.list_records()) == 12


@pytest.mark.parametrize("loss_offset,confirmed", [(1, True), (4, False), (5, False)])
def test_imported_health_loss_preserves_only_newer_confirmed_evidence(
    store, native_capabilities, event_factory, now, loss_offset, confirmed
):
    store.register_source(native_capabilities, enabled=True, qualified=True)
    store.ingest(
        event_factory(
            native=True,
            event_kind="source.health",
            event_id="known-loss",
            captured_at=now + timedelta(minutes=2),
            payload_changes={"connection_state": "disconnected"},
        ),
        received_at=now + timedelta(minutes=2),
    )
    first = store.ingest(
        event_factory(
            native=True,
            current=True,
            restored=True,
            captured_at=now + timedelta(minutes=4),
        ),
        received_at=now + timedelta(minutes=4),
    )
    store.ingest(
        event_factory(
            native=True,
            event_kind="source.health",
            event_id="imported-loss",
            captured_at=now + timedelta(minutes=loss_offset),
            payload_changes={"connection_state": "disconnected"},
        ),
        received_at=now + timedelta(minutes=6),
    )
    record = store.get_record(first.record_id).projection
    assert record.current_confirmed is confirmed
    assert record.last_confirmed_at == now + timedelta(minutes=4)


@pytest.mark.parametrize("traffic", ["duplicate", "stale", "conflict", "non_substantive"])
def test_compact_record_cannot_renew_sensitive_body_through_repeated_traffic(
    store, event_factory, now, traffic
):
    marker = {"title": "SYNTHETIC-DETAIL-MARKER"}
    first = store.ingest(event_factory(snapshot_changes=marker), received_at=now)
    store.ingest(event_factory(revision=3, snapshot_changes=marker), received_at=now)
    store.age_records(now=now + timedelta(hours=1))
    later = now + timedelta(days=31)
    store.age_records(now=later)
    assert not store.get_record(first.record_id).detail_retained
    kwargs = {"revision": 3, "snapshot_changes": marker}
    if traffic == "stale":
        kwargs["revision"] = 2
    elif traffic == "conflict":
        kwargs["snapshot_changes"] = {"title": "SYNTHETIC-CONFLICT-MARKER"}
    elif traffic == "non_substantive":
        kwargs["revision"] = 4
    repeated = event_factory(event_id="new-transport", captured_at=later, **kwargs)
    receipt = store.ingest(repeated, received_at=later)
    assert receipt.category == ("apply" if traffic == "non_substantive" else traffic)
    compact = store.get_record(first.record_id)
    assert not compact.detail_retained and compact.projection.snapshot is None
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 3
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] >= 2
    replay = store.ingest(repeated, received_at=later + timedelta(seconds=1))
    assert replace(replay, replayed=False) == receipt
    store.age_records(now=now + timedelta(days=365))
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 0
    # Fresh substantive evidence may legitimately renew retained detail.
    fresh_time = now + timedelta(days=366)
    fresh = store.ingest(
        event_factory(
            revision=5,
            captured_at=fresh_time,
            snapshot_changes={"title": "Fresh material evidence"},
        ),
        received_at=fresh_time,
    )
    assert fresh.category == "apply"
    renewed = store.get_record(first.record_id)
    assert renewed.detail_retained and not renewed.projection.aged
    assert renewed.short_reference == first.short_reference
    with store.read_snapshot() as db:
        bodies = db.execute("SELECT body FROM event_details").fetchall()
        assert len(bodies) == 1
        assert "Fresh material evidence" in bodies[0][0]
        assert "SYNTHETIC-" not in bodies[0][0]


def test_standalone_health_and_live_orphan_bodies_expire_independently(
    store, native_capabilities, event_factory, now
):
    store.register_source(native_capabilities, enabled=True, qualified=True)
    store.ingest(event_factory(native=True, event_kind="source.health"), received_at=now)
    first = store.ingest(
        event_factory(native=True, event_kind="execution.updated"), received_at=now
    )
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 2
    store.age_records(now=now + timedelta(days=31))
    assert store.get_record(first.record_id).projection.execution_state == "running"
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 2


@pytest.mark.parametrize("previously_exists", [False, True])
def test_restore_audit_receipt_association_is_frozen_across_fresh_event_and_restart(
    tmp_path, explicit_capabilities, event_factory, now, previously_exists
):
    with SQLiteStore(tmp_path / "original" / "mesh.db", now=now) as original:
        original.register_source(explicit_capabilities)
        existing = original.ingest(event_factory(), received_at=now) if previously_exists else None
        backup = original.backup(tmp_path / "backup" / "mesh.db")
    path = tmp_path / "restored" / "mesh.db"
    old = event_factory(event_id="old-missing", revision=2)
    with SQLiteStore.restore_backup(backup, path, now=now + timedelta(minutes=1)) as store:
        receipt = store.ingest(old, received_at=now + timedelta(minutes=2))
        assert "pre_restore_audit_only" in receipt.flags
        assert receipt.record_id == (existing.record_id if existing else None)
        fresh_at = now + timedelta(minutes=3)
        fresh = store.ingest(
            event_factory(
                revision=3,
                event_id="fresh",
                captured_at=fresh_at,
                snapshot_changes={"title": "Fresh material evidence"},
            ),
            received_at=fresh_at,
        )
        assert fresh.record_id is not None
        assert replace(store.ingest(old, received_at=fresh_at), replayed=False) == receipt
    with SQLiteStore(path, now=now + timedelta(minutes=4)) as reopened:
        replay = reopened.ingest(old, received_at=now + timedelta(minutes=4))
        assert replace(replay, replayed=False) == receipt
        assert replay.replayed
        reopened.age_records(now=now + timedelta(hours=2))
        reopened.age_records(now=now + timedelta(days=365))
        with reopened.read_snapshot() as db:
            assert db.execute("SELECT count(*) FROM event_details").fetchone()[0] == 0


def _downgrade_synthetic_schema_to_v1(db):
    # A real v1-shaped temporary DB, not a reset or production downgrade API.
    db.execute("DROP INDEX records_reducer")
    db.execute("ALTER TABLE records DROP COLUMN reducer_retained")
    db.execute("DELETE FROM schema_versions WHERE version>1")
    db.execute("PRAGMA user_version=1")


@pytest.mark.parametrize("restore", [False, True])
def test_schema_v1_migration_preserves_live_orphans_and_repairs_audit_associations(
    tmp_path, explicit_capabilities, native_capabilities, event_factory, now, restore
):
    from decision_mesh.storage import SCHEMA_VERSION

    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as original:
        original.register_source(explicit_capabilities)
        original.ingest(event_factory(request_id="existing", event_id="existing"), received_at=now)
        backup = original.backup(tmp_path / "backup" / "mesh.db")
    restored_path = tmp_path / "restored" / "mesh.db"
    old = event_factory(event_id="old-missing")
    old_existing = event_factory(request_id="existing", event_id="old-existing", revision=2)
    with SQLiteStore.restore_backup(backup, restored_path, now=now + timedelta(seconds=1)) as store:
        absent_receipt = store.ingest(old, received_at=now + timedelta(seconds=2))
        present_receipt = store.ingest(old_existing, received_at=now + timedelta(seconds=2))
        fresh = store.ingest(
            event_factory(
                event_id="fresh",
                revision=2,
                captured_at=now + timedelta(seconds=3),
                snapshot_changes={"title": "Fresh"},
            ),
            received_at=now + timedelta(seconds=3),
        )
        store.register_source(native_capabilities, enabled=True, qualified=True)
        orphan = store.ingest(
            event_factory(
                native=True,
                event_kind="execution.updated",
                captured_at=now + timedelta(seconds=3),
            ),
            received_at=now + timedelta(seconds=3),
        )
        with store.transaction() as db:
            # v1 stored the prospective key even when no record existed yet.
            db.execute(
                "UPDATE events SET record_key=(SELECT record_key FROM records WHERE record_id=?) "
                "WHERE event_id='old-missing'",
                (fresh.record_id,),
            )
            _downgrade_synthetic_schema_to_v1(db)
    migrated = (
        SQLiteStore.restore_backup(
            restored_path, tmp_path / "v1-restored" / "mesh.db", now=now + timedelta(seconds=4)
        )
        if restore
        else SQLiteStore(restored_path, now=now + timedelta(seconds=4))
    )
    with migrated as store:
        assert (
            replace(store.ingest(old, received_at=now + timedelta(seconds=5)), replayed=False)
            == absent_receipt
        )
        assert (
            replace(
                store.ingest(old_existing, received_at=now + timedelta(seconds=5)), replayed=False
            )
            == present_receipt
        )
        assert store.get_record(orphan.record_id).projection.connection_state == "disconnected"
        with store.read_snapshot() as db:
            assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        # Opening/restore created a protected SQLite backup before additive migration.
        assert len(list(store.path.parent.glob("*.pre-v2-*.bak"))) == 1


def test_failed_v1_additive_migration_leaves_original_records_and_backup(
    tmp_path, explicit_capabilities, event_factory, now, monkeypatch
):
    from decision_mesh import storage

    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as store:
        store.register_source(explicit_capabilities)
        receipt = store.ingest(event_factory(), received_at=now)
        with store.transaction() as db:
            _downgrade_synthetic_schema_to_v1(db)
    migration = storage.MIGRATIONS[2]
    monkeypatch.setitem(storage.MIGRATIONS, 2, (*migration, "INVALID SQL"))
    with pytest.raises(StorageError):
        SQLiteStore(path, now=now)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert "reducer_retained" not in {
            row[1] for row in db.execute("PRAGMA table_info(records)")
        }
        assert (
            db.execute("SELECT short_reference FROM records").fetchone()[0]
            == receipt.short_reference
        )
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    backup = next(path.parent.glob("*.pre-v2-*.bak"))
    with sqlite3.connect(backup) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    monkeypatch.setitem(storage.MIGRATIONS, 2, migration)
    with SQLiteStore(path, now=now) as reopened:
        assert reopened.get_record(receipt.record_id).short_reference == receipt.short_reference


@pytest.mark.parametrize("legacy_v1", [False, True])
def test_reopen_enforces_live_bound_before_loading_reducer_state(
    tmp_path, native_capabilities, event_factory, now, monkeypatch, legacy_v1
):
    from decision_mesh import storage

    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, detail_limit=2, now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        for number in range(2):
            store.ingest(
                event_factory(
                    native=True,
                    event_kind="execution.updated",
                    request_id=str(number),
                    event_id=str(number),
                ),
                received_at=now,
            )
        if legacy_v1:
            with store.transaction() as db:
                _downgrade_synthetic_schema_to_v1(db)

    def unexpected(*args, **kwargs):
        pytest.fail("source-wide allocation occurred before enforcing live-state capacity")

    with monkeypatch.context() as patch:
        patch.setattr(storage, "disconnect_source", unexpected)
        with pytest.raises(CapacityError):
            SQLiteStore(path, detail_limit=1, now=now)
    with SQLiteStore(path, detail_limit=2, now=now) as reopened:
        assert len(reopened.list_records()) == 2
        assert counts(reopened)[0] == 2


def test_checked_alias_rejects_stale_profile_without_mutation(store, now):
    alias = store.project_alias("app")
    stale = store.get_settings()
    current = store.update_settings(stale.revision, {"device_alias": "Study"}, now=now)
    with pytest.raises(SettingsConflict, match="stale_settings_revision"):
        store.rename_alias_checked(alias.identity, "Stale change", expected_revision=stale.revision)
    assert store.project_alias("app") == alias
    assert store.get_settings() == current


def test_checked_alias_only_first_same_revision_writer_commits(store):
    alias = store.project_alias("app")
    revision = store.get_settings().revision
    committed = store.rename_alias_checked(alias.identity, "First", expected_revision=revision)
    with pytest.raises(SettingsConflict):
        store.rename_alias_checked(alias.identity, "Second", expected_revision=revision)
    assert store.project_alias("app").alias == "First"
    assert store.get_settings() == committed
    assert committed.revision == revision + 1


def test_checked_alias_concurrent_writers_share_profile_guard(store):
    alias = store.project_alias("app")
    revision = store.get_settings().revision

    def rename(value):
        try:
            return value, store.rename_alias_checked(
                alias.identity, value, expected_revision=revision
            )
        except SettingsConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(rename, ["First", "Second"]))
    accepted = [result for result in results if result is not None]
    assert len(accepted) == 1
    name, committed = accepted[0]
    assert store.project_alias("app").alias == name
    assert store.get_settings() == committed
    assert committed.revision == revision + 1


@pytest.mark.parametrize("invalid_alias", ["", " ", "private\nvalue", "x" * 81, None])
def test_invalid_alias_preserves_alias_and_profile(store, invalid_alias):
    alias = store.project_alias("app")
    current = store.get_settings()
    with pytest.raises(SettingsError, match="invalid_alias"):
        store.rename_alias_checked(
            alias.identity, invalid_alias, expected_revision=current.revision
        )
    assert store.project_alias("app") == alias
    assert store.get_settings() == current


@pytest.mark.parametrize("revision", [None, True, "0", -1])
def test_checked_alias_requires_exact_integer_current_revision(store, revision):
    alias = store.project_alias("app")
    current = store.get_settings()
    with pytest.raises(SettingsConflict):
        store.rename_alias_checked(alias.identity, "Changed", expected_revision=revision)
    assert store.project_alias("app") == alias
    assert store.get_settings() == current


def test_missing_alias_preserves_existing_alias_and_profile(store):
    alias = store.project_alias("app")
    current = store.get_settings()
    with pytest.raises(SettingsError, match="project_alias_not_found"):
        store.rename_alias_checked(
            "identity:missing", "Changed", expected_revision=current.revision
        )
    assert store.project_alias("app") == alias
    assert store.get_settings() == current
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM aliases").fetchone()[0] == 1


@pytest.mark.parametrize("checked", [False, True])
def test_alias_and_profile_rollback_together_if_profile_write_fails(store, checked):
    alias = store.project_alias("app")
    current = store.get_settings()
    with store.transaction() as db:
        db.execute(
            "CREATE TEMP TRIGGER reject_profile_write BEFORE UPDATE ON settings "
            "BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END"
        )
    with pytest.raises(StorageError, match="database_transaction_failed"):
        if checked:
            store.rename_alias_checked(
                alias.identity, "Changed", expected_revision=current.revision
            )
        else:
            store.rename_alias(alias.identity, "Changed")
    assert store.project_alias("app") == alias
    assert store.get_settings() == current


def test_legacy_and_same_value_alias_writes_advance_profile_revision(store, now):
    alias = store.project_alias("app")
    original = store.get_settings()
    assert store.rename_alias(alias.identity, "Changed") is None
    legacy = store.get_settings()
    assert legacy.revision == original.revision + 1
    with pytest.raises(SettingsConflict):
        store.update_settings(original.revision, {"device_alias": "Stale"}, now=now)
    checked = store.rename_alias_checked(
        alias.identity, "Changed", expected_revision=legacy.revision
    )
    assert checked.revision == legacy.revision + 1
    assert store.get_settings() == checked
    assert store.rename_alias(alias.identity, "Changed") is None
    assert store.get_settings().revision == checked.revision + 1
    assert store.project_alias("app").alias == "Changed"


def test_alias_writes_preserve_route_grants_eligibility_and_source_state(store, event_factory, now):
    activate(store, now)
    original = store.update_settings(
        store.get_settings().revision, {"disclosure_fields": ["action"]}, now=now
    )
    policy = store.current_policy()
    receipt = store.ingest(event_factory(capture_policy_ref=policy.policy_ref), received_at=now)
    record = store.get_record(receipt.record_id)
    eligibility = store.eligibility_after()
    alias = store.project_alias("app", local_path="D:/private-project")
    with store.read_snapshot() as db:
        policy_count = db.execute("SELECT count(*) FROM policies").fetchone()[0]
    checked = store.rename_alias_checked(
        alias.identity, "Work", expected_revision=original.revision
    )
    assert checked == original.model_copy(update={"revision": original.revision + 1})
    store.rename_alias(alias.identity, "Research")
    assert store.get_settings() == original.model_copy(update={"revision": original.revision + 2})
    assert store.current_policy() == policy
    assert store.get_policy(policy.policy_ref) == policy
    assert policy.permits_route(store.get_settings())
    assert policy.effective_fields(store.get_settings()) == original.disclosure_fields
    assert store.eligibility_after() == eligibility
    assert store.get_record(receipt.record_id) == record
    with store.read_snapshot() as db:
        assert db.execute("SELECT count(*) FROM policies").fetchone()[0] == policy_count
    assert store.project_alias("app").local_path == alias.local_path
