"""Importer boundary tests against real SQLite and deliberately failing sinks."""

import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from decision_mesh.capture import atomic_write_owner_only, ensure_spool_dir, write_envelope
from decision_mesh.contracts import MAX_EVENT_BYTES, EventKind, SourceState
from decision_mesh.ingestion import SpoolImporter
from decision_mesh.producer import ExplicitProducer, enroll_producer
from decision_mesh.settings import DestinationIdentity
from decision_mesh.storage import SQLiteStore


@pytest.fixture
def store(tmp_path, now, explicit_capabilities):
    with SQLiteStore(tmp_path / "store" / "mesh.db", now=now) as value:
        value.register_source(explicit_capabilities)
        yield value


@pytest.fixture
def spool(tmp_path):
    return ensure_spool_dir(tmp_path / "spool")


def ready(spool, event):
    return write_envelope(spool, event.model_dump(mode="json")).path


def event_counts(store):
    with store.read_snapshot() as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
            for name in ("events", "records", "eligibility")
        )


def test_sorted_import_uses_original_capture_time_and_store_receipt(
    store, spool, explicit_capabilities, event_factory, now
):
    early = event_factory(
        request_id="early", event_id="early", captured_at=now - timedelta(hours=2)
    )
    late = event_factory(request_id="late", event_id="late")
    ready(spool, late)
    ready(spool, early)
    importer = SpoolImporter(spool, explicit_capabilities, store)
    result = importer.run_once(now=now)
    assert result.imported == result.scanned == 2
    assert result.quarantined == result.deferred == 0
    assert not list(spool.glob("*.json"))
    with store.read_snapshot() as db:
        rows = db.execute("SELECT event_id,captured_at FROM events ORDER BY sequence").fetchall()
    assert [row["event_id"] for row in rows] == ["early", "late"]
    assert store.list_records()[0].projection.captured_at in {early.captured_at, late.captured_at}
    records = {r.projection.key[1]: r for r in store.list_records()}
    assert records["early"].projection.visibility == "history"
    assert records["early"].projection.aging_deadline == early.captured_at + timedelta(minutes=60)


def test_commit_then_delete_failure_replays_original_receipt(
    store, spool, explicit_capabilities, event_factory, now, monkeypatch
):
    path = ready(spool, event_factory())
    real_unlink = Path.unlink

    def deny_delete(target, *args, **kwargs):
        if target == path:
            raise PermissionError("synthetic secret must not log")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_delete)
    first = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert first.imported == first.deferred == 1 and path.exists()
    assert first.diagnostics == {"delete_deferred": 1}
    assert event_counts(store) == (1, 1, 1)
    original = store.ingest(event_factory(), received_at=now)
    monkeypatch.setattr(Path, "unlink", real_unlink)
    second = SpoolImporter(spool, explicit_capabilities, store).run_once(
        now=now + timedelta(minutes=1)
    )
    replay = store.ingest(event_factory(), received_at=now + timedelta(minutes=1))
    assert second.replayed == second.imported == 1 and not path.exists()
    assert replay == original
    assert event_counts(store) == (1, 1, 1)


def test_real_crash_after_store_commit_retains_spool_then_replays(
    tmp_path, spool, explicit_capabilities, event_factory, now
):
    database = tmp_path / "store" / "mesh.db"
    with SQLiteStore(database, now=now) as setup:
        setup.register_source(explicit_capabilities)
    path = ready(spool, event_factory())
    script = """
import json, os, sys
from datetime import datetime
from decision_mesh.contracts import SourceCapabilities
from decision_mesh.ingestion import SpoolImporter
from decision_mesh.storage import SQLiteStore
now = datetime.fromisoformat(sys.argv[3])
def crash(point):
    if point == 'committed':
        os._exit(74)
with SQLiteStore(sys.argv[1], now=now, fault_hook=crash) as store:
    capabilities = SourceCapabilities.model_validate_json(sys.stdin.buffer.read())
    SpoolImporter(sys.argv[2], capabilities, store).run_once(now=now)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(database), str(spool), now.isoformat()],
        input=explicit_capabilities.model_dump_json().encode(),
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 74, result.stderr.decode()
    assert path.exists()
    with SQLiteStore(database, now=now) as reopened:
        assert event_counts(reopened) == (1, 1, 1)
        result = SpoolImporter(spool, explicit_capabilities, reopened).run_once(now=now)
        assert result.imported == result.replayed == 1
        assert event_counts(reopened) == (1, 1, 1)
    assert not path.exists()


def test_invalid_ready_files_do_not_block_valid_files(
    store, spool, explicit_capabilities, event_factory, now
):
    atomic_write_owner_only(spool / "000-invalid.json", b'{"secret":"bad"')
    atomic_write_owner_only(
        spool / "001-duplicates.json", b'{"schema_version":1,"schema_version":1}'
    )
    atomic_write_owner_only(spool / "002-nan.json", b'{"schema_version":NaN}')
    ready(spool, event_factory())
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.imported == 1 and result.quarantined == 3
    assert result.diagnostics == {"invalid_event": 3}
    assert len(list((spool / ".quarantine").glob("*.bad"))) == 3


@pytest.mark.parametrize(
    "age,accepted",
    [
        (timedelta(days=30), True),
        (timedelta(days=30, microseconds=1), False),
        (-timedelta(minutes=5), True),
        (-timedelta(minutes=5, microseconds=1), False),
    ],
)
def test_capture_time_acceptance_limits(
    store, spool, explicit_capabilities, event_factory, now, age, accepted
):
    ready(spool, event_factory(captured_at=now - age))
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.imported == int(accepted)
    assert result.quarantined == int(not accepted)


def test_size_limit_discards_huge_entry_with_bounded_diagnostics(
    store, spool, explicit_capabilities, event_factory, now
):
    atomic_write_owner_only(
        spool / "huge.json", b"x" * (MAX_EVENT_BYTES + 1), max_bytes=MAX_EVENT_BYTES + 1
    )
    ready(spool, event_factory())
    importer = SpoolImporter(spool, explicit_capabilities, store)
    result = importer.run_once(now=now)
    assert result.quarantined == result.discarded == result.imported == 1
    assert result.diagnostics["event_too_large"] == 1
    assert result.diagnostics["quarantine_discarded"] == 1
    assert (
        sum(p.stat().st_size for p in importer.quarantine_dir.iterdir() if p.is_file())
        <= importer.max_quarantine_bytes
    )


def test_quarantine_prunes_oldest_and_keeps_cumulative_safe_counts(
    store, spool, explicit_capabilities, now
):
    importer = SpoolImporter(spool, explicit_capabilities, store, max_quarantine_bytes=8192)
    atomic_write_owner_only(spool / "first.json", b"A" * 3000)
    first = importer.run_once(now=now)
    old = next(importer.quarantine_dir.glob("*.bad"))
    os.utime(old, (1, 1))
    atomic_write_owner_only(spool / "second.json", b"B" * 3000)
    second = importer.run_once(now=now)
    assert first.quarantined == second.quarantined == second.pruned == 1
    assert not old.exists()
    retained = list(importer.quarantine_dir.glob("*.bad"))
    assert len(retained) == 1 and retained[0].read_bytes() == b"B" * 3000
    diagnostic = json.loads((importer.quarantine_dir / ".diagnostics.json").read_bytes())
    assert diagnostic["counts"]["invalid_event"] == 2
    assert diagnostic["counts"]["quarantine_pruned"] == 1
    assert sum(p.stat().st_size for p in importer.quarantine_dir.iterdir() if p.is_file()) <= 8192


def test_identity_conflicts_quarantined_without_overwrite(
    store, spool, explicit_capabilities, event_factory, now
):
    original = event_factory()
    receipt = store.ingest(original, received_at=now)
    before = store.get_record(receipt.record_id)
    ready(spool, event_factory(snapshot_changes={"title": "changed secret"}))
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.quarantined == 1 and result.diagnostics == {"identity_conflict": 1}
    assert store.get_record(receipt.record_id) == before
    assert event_counts(store) == (1, 1, 1)


def test_revision_conflict_is_also_quarantined(
    store, spool, explicit_capabilities, event_factory, now
):
    store.ingest(event_factory(), received_at=now)
    ready(spool, event_factory(event_id="different", snapshot_changes={"title": "different"}))
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.quarantined == 1 and result.diagnostics == {"identity_conflict": 1}
    assert len(store.list_records()) == 1


def test_source_entrypoint_blocks_cross_namespace_and_does_not_enroll(
    store, spool, explicit_capabilities, event_factory, now
):
    ready(spool, event_factory(producer_id="foreign-agent"))
    ready(spool, event_factory(native=True))
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.quarantined == 2
    assert result.diagnostics == {"source_namespace_mismatch": 2}
    assert store.source_registration("foreign-agent") is None
    assert store.source_registration("codex-native") is None
    assert event_counts(store) == (0, 0, 0)


def test_manifest_capability_limit_before_sink(
    store, spool, explicit_capabilities, event_factory, now
):
    manifest = explicit_capabilities.model_copy(
        update={"allowed_event_kinds": (EventKind.REQUEST_OPENED,)}
    )
    ready(spool, event_factory(event_kind="request.updated"))
    result = SpoolImporter(spool, manifest, store).run_once(now=now)
    assert result.quarantined == 1
    assert result.diagnostics == {"source_capability_mismatch": 1}
    assert event_counts(store) == (0, 0, 0)


def test_disabled_source_is_retained_for_controlled_repair(
    store, spool, explicit_capabilities, event_factory, now
):
    store.register_source(explicit_capabilities, enabled=False)
    path = ready(spool, event_factory())
    first = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert first.deferred == 1 and path.exists()
    assert not store.source_registration(explicit_capabilities.producer_id)["enabled"]
    store.register_source(explicit_capabilities)
    assert SpoolImporter(spool, explicit_capabilities, store).run_once(now=now).imported == 1


def test_no_raw_sink_errors_or_file_names_in_diagnostics(
    store, spool, explicit_capabilities, event_factory, now, capsys
):
    secret = "synthetic-secret-do-not-log"

    class Broken:
        def ingest(self, *_args, **_kwargs):
            raise RuntimeError(secret)

    ready(spool, event_factory(snapshot_changes={"title": secret}))
    atomic_write_owner_only(spool / (secret + ".json"), b"invalid")
    importer = SpoolImporter(spool, explicit_capabilities, Broken())
    result = importer.run_once(now=now)
    assert result.deferred == result.quarantined == 1
    assert secret not in str(result)
    assert secret not in (importer.quarantine_dir / ".diagnostics.json").read_text()
    assert capsys.readouterr() == ("", "")


def test_invalid_sink_receipt_cannot_delete_ready_file(
    store, spool, explicit_capabilities, event_factory, now
):
    class Broken:
        def ingest(self, *_args, **_kwargs):
            return object()

    path = ready(spool, event_factory())
    result = SpoolImporter(spool, explicit_capabilities, Broken()).run_once(now=now)
    assert result.deferred == 1 and path.exists()
    assert result.diagnostics == {"sink_receipt_invalid": 1}


def test_atomic_precommit_failure_keeps_spool(
    store, spool, explicit_capabilities, event_factory, now
):
    class Failing:
        def ingest(self, event, **kwargs):
            # The actual SQLite transaction fails before its context commits.
            with store.transaction() as db:
                db.execute("INSERT INTO diagnostics VALUES ('temporary',1)")
                raise OSError("disk failure")

    path = ready(spool, event_factory())
    result = SpoolImporter(spool, explicit_capabilities, Failing()).run_once(now=now)
    assert result.deferred == 1 and path.exists()
    with store.read_snapshot() as db:
        assert (
            db.execute("SELECT count(*) FROM diagnostics WHERE code='temporary'").fetchone()[0] == 0
        )
    assert event_counts(store) == (0, 0, 0)


def test_source_symlink_and_unsafe_entry_rejected_without_following(
    store, spool, explicit_capabilities, event_factory, now, tmp_path
):
    target = tmp_path / "outside"
    ensure_spool_dir(target)
    secret = target / "private.json"
    atomic_write_owner_only(secret, b"unreadable secret")
    link = spool / "000-link.json"
    try:
        link.symlink_to(secret)
    except OSError:
        # Hard links also fail the importer's single-link regular-file contract
        # without requiring Windows developer-mode symbolic link permission.
        os.link(secret, link)
    ready(spool, event_factory())
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.unsafe == result.imported == 1
    assert secret.read_bytes() == b"unreadable secret" and link.exists()


def test_directory_ready_name_rejected_and_valid_entry_continues(
    store, spool, explicit_capabilities, event_factory, now
):
    ensure_spool_dir(spool / "000-directory.json")
    ready(spool, event_factory())
    result = SpoolImporter(spool, explicit_capabilities, store).run_once(now=now)
    assert result.unsafe == result.imported == 1


def test_batch_limit_and_partial_files(store, spool, explicit_capabilities, event_factory, now):
    for index in range(3):
        ready(spool, event_factory(request_id=str(index), event_id=str(index)))
    atomic_write_owner_only(spool / ".capture-orphan.part", b"unaccepted")
    importer = SpoolImporter(spool, explicit_capabilities, store)
    assert importer.run_once(now=now, limit=2).imported == 2
    assert importer.run_once(now=now, limit=2).imported == 1
    assert (spool / ".capture-orphan.part").exists()


def test_policy_generations_retry_and_delayed_age_end_to_end(tmp_path, now):
    root = tmp_path / "producer"
    enrollment = enroll_producer(root)
    policy_path = root / "policy.json"
    with SQLiteStore(tmp_path / "store" / "mesh.db", now=now) as store:
        store.register_source(enrollment.capabilities)
        store.update_settings(
            store.get_settings().revision,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=123, bot_id=456)},
            now=now,
        )
        store.publish_capture_policy(policy_path)
        producer = ExplicitProducer(root, policy_path=policy_path, clock=lambda: now)
        first = producer.create(
            {
                "source_request_id": "old",
                "snapshot": {"kind": "question"},
                "idempotency_key": "first",
            }
        )
        store.update_settings(
            store.get_settings().revision, {"channel_active": False}, now=now + timedelta(minutes=1)
        )
        store.update_settings(
            store.get_settings().revision, {"channel_active": True}, now=now + timedelta(minutes=2)
        )
        store.publish_capture_policy(policy_path)
        later = ExplicitProducer(
            root, policy_path=policy_path, clock=lambda: now + timedelta(hours=2)
        )
        replay = later.create(
            {
                "source_request_id": "old",
                "snapshot": {"kind": "question"},
                "idempotency_key": "first",
            }
        )
        assert (
            replay.capture_policy_ref
            == first.capture_policy_ref
            != store.current_policy().policy_ref
        )
        result = SpoolImporter(later.spool_dir, later.capabilities, store).run_once(
            now=now + timedelta(hours=2)
        )
        assert result.imported == 1
        assert store.eligibility_after()[0].kind == "local_only"
        record = store.list_records()[0].projection
        assert record.visibility == "history" and record.source_state == SourceState.UNVERIFIED
        assert record.captured_at == now


def test_native_store_namespace_cannot_be_resolved_by_explicit_producer(
    tmp_path, now, native_capabilities, event_factory
):
    root = tmp_path / "producer"
    enrollment = enroll_producer(root)
    with SQLiteStore(tmp_path / "store" / "mesh.db", now=now) as store:
        store.register_source(native_capabilities, qualified=True, enabled=True)
        store.register_source(enrollment.capabilities)
        native = event_factory(native=True)
        receipt = store.ingest(native, received_at=now)
        before = store.get_record(receipt.record_id)
        producer = ExplicitProducer(root, clock=lambda: now)
        producer.resolve(
            {"source_request_id": native.source_request_id, "snapshot": {"kind": "question"}}
        )
        SpoolImporter(producer.spool_dir, producer.capabilities, store).run_once(now=now)
        assert store.get_record(receipt.record_id) == before
        assert len(store.list_records()) == 2
        own = next(
            record
            for record in store.list_records()
            if record.projection.key[0] == enrollment.producer_id
        )
        assert own.projection.source_state == SourceState.AGENT_RESOLVED


def test_retained_unsafe_prefix_does_not_starve_next_batch(
    store, spool, explicit_capabilities, event_factory, now
):
    ensure_spool_dir(spool / "000-unsafe.json")
    atomic_write_owner_only(spool / ".hidden.json", b"not-ready")
    ready(spool, event_factory())
    importer = SpoolImporter(spool, explicit_capabilities, store)
    assert importer.run_once(now=now, limit=1).unsafe == 1
    assert importer.run_once(now=now, limit=1).imported == 1
    assert (spool / ".hidden.json").exists()


def test_empty_quarantine_files_have_separate_count_bound(
    store, spool, explicit_capabilities, now, monkeypatch
):
    import decision_mesh.ingestion as module

    monkeypatch.setattr(module, "_MAX_QUARANTINE_FILES", 2)
    for index in range(4):
        atomic_write_owner_only(spool / f"empty-{index}.json", b"")
    importer = SpoolImporter(spool, explicit_capabilities, store)
    result = importer.run_once(now=now)
    assert result.quarantined == 4 and result.pruned == 2
    assert len(list(importer.quarantine_dir.glob("*.bad"))) == 2


def test_cumulative_diagnostics_saturate_instead_of_overflowing(
    store, spool, explicit_capabilities, now
):
    importer = SpoolImporter(spool, explicit_capabilities, store)
    diagnostic_path = importer.quarantine_dir / ".diagnostics.json"
    atomic_write_owner_only(
        diagnostic_path,
        json.dumps({"schema_version": 1, "counts": {"invalid_event": 2**63 - 1}}).encode(),
    )
    atomic_write_owner_only(spool / "invalid.json", b"no")
    result = importer.run_once(now=now)
    assert result.quarantined == 1
    assert json.loads(diagnostic_path.read_bytes())["counts"]["invalid_event"] == 2**63 - 1


def test_unenrolled_manifest_does_not_register_itself(
    store, spool, explicit_capabilities, event_factory, now
):
    manifest = explicit_capabilities.model_copy(update={"producer_id": "not-enrolled"})
    path = ready(spool, event_factory(producer_id="not-enrolled"))
    result = SpoolImporter(spool, manifest, store).run_once(now=now)
    assert result.deferred == 1 and path.exists()
    assert store.source_registration("not-enrolled") is None


def test_unqualified_native_identity_is_quarantined(
    store, spool, native_capabilities, event_factory, now
):
    from decision_mesh.contracts import validate_event

    store.register_source(native_capabilities, qualified=True, enabled=True)
    raw = event_factory(native=True).model_dump(mode="json")
    raw["source_request_id"] = "wrong-documented-identity"
    ready(spool, validate_event(raw))
    result = SpoolImporter(spool, native_capabilities, store).run_once(now=now)
    assert result.quarantined == 1
    assert result.diagnostics == {"source_unqualified": 1}
    assert len(store.list_records()) == 0


def test_retry_after_successful_import_does_not_create_another_occurrence(tmp_path, now):
    root = tmp_path / "producer"
    enrollment = enroll_producer(root)
    producer = ExplicitProducer(root, clock=lambda: now)
    document = {
        "source_request_id": "stable",
        "snapshot": {"kind": "question"},
        "idempotency_key": "same",
    }
    with SQLiteStore(tmp_path / "store" / "mesh.db", now=now) as store:
        store.register_source(enrollment.capabilities)
        first = producer.create(document)
        importer = SpoolImporter(producer.spool_dir, producer.capabilities, store)
        assert importer.run_once(now=now).imported == 1
        assert not first.path.exists()
        retry = producer.create(document)
        assert retry.event_id == first.event_id and retry.path.exists()
        result = importer.run_once(now=now + timedelta(minutes=1))
        assert result.replayed == result.imported == 1
        assert event_counts(store) == (1, 1, 1)


def test_unknown_current_policy_reference_remains_local_only(tmp_path, now):
    root = tmp_path / "producer"
    enrollment = enroll_producer(root)
    policy_path = root / "policy.json"
    atomic_write_owner_only(
        policy_path,
        b'{"schema_version":1,"channel_active":true,"capture_policy_ref":"stale-unknown-grant"}',
    )
    producer = ExplicitProducer(root, policy_path=policy_path, clock=lambda: now)
    producer.create({"source_request_id": "stale", "snapshot": {"kind": "question"}})
    with SQLiteStore(tmp_path / "store" / "mesh.db", now=now) as store:
        store.register_source(enrollment.capabilities)
        store.update_settings(
            store.get_settings().revision,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=123, bot_id=456)},
            now=now,
        )
        result = SpoolImporter(producer.spool_dir, producer.capabilities, store).run_once(now=now)
        assert result.imported == 1
        assert store.eligibility_after()[0].kind == "local_only"


@pytest.mark.parametrize("limit", [0, 4097, True])
def test_import_batch_rejects_unbounded_or_boolean_limits(
    store, spool, explicit_capabilities, now, limit
):
    from decision_mesh.ingestion import IngestionError

    importer = SpoolImporter(spool, explicit_capabilities, store)
    with pytest.raises(IngestionError, match="invalid_import_limit"):
        importer.run_once(now=now, limit=limit)


def test_failed_quarantine_prune_preserves_source_and_does_not_claim_deletion(
    store, spool, explicit_capabilities, now, monkeypatch
):
    importer = SpoolImporter(spool, explicit_capabilities, store, max_quarantine_bytes=8192)
    atomic_write_owner_only(spool / "first.json", b"A" * 3000)
    importer.run_once(now=now)
    old = next(importer.quarantine_dir.glob("*.bad"))
    atomic_write_owner_only(spool / "second.json", b"B" * 3000)
    original_unlink = Path.unlink

    def deny_prune(path, *args, **kwargs):
        if path == old:
            raise PermissionError("synthetic lock")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_prune)
    result = importer.run_once(now=now)
    assert result.deferred == 1 and result.pruned == result.quarantined == 0
    assert old.exists() and (spool / "second.json").exists()
    diagnostic = json.loads((importer.quarantine_dir / ".diagnostics.json").read_bytes())
    assert diagnostic["counts"].get("quarantine_pruned", 0) == 0
