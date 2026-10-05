"""Bounded read evidence, exact view parity and retained-history scalability."""

import base64
import json
from dataclasses import asdict, replace
from datetime import timedelta
from itertools import product

import pytest

from decision_mesh.contracts import EvidenceClass, SourceState
from decision_mesh.domain import RequestProjection, VisibilityState
from decision_mesh.presentation.models import PresentationStatus
from decision_mesh.storage import PROJECTION, SQLiteStore, StorageError
from decision_mesh.storage_queries import decode_cursor, encode_cursor
from decision_mesh.view import record_view


@pytest.fixture
def store(tmp_path, now, explicit_capabilities):
    with SQLiteStore(tmp_path / "data" / "mesh.db", now=now) as value:
        value.register_source(explicit_capabilities)
        yield value


def test_filtered_counts_and_pages_match_view_precedence(store, event_factory, now):
    snapshot = event_factory().payload.snapshot
    source_cases = list(product(SourceState, (False, True), EvidenceClass))
    metadata_cases = [
        (True, True, False, None),
        (True, True, True, None),
        (True, True, False, now + timedelta(microseconds=1)),
        (True, True, False, now),
        (False, False, False, None),
        (True, False, False, None),
        (False, True, False, None),
    ]
    expected = []
    with store.transaction() as db:
        for i, (
            (state, confirmed, evidence),
            (has_snapshot, detail, seen, snooze),
            flags,
        ) in enumerate(
            product(
                source_cases,
                metadata_cases,
                [
                    (False, False, False),
                    (True, True, False),
                    (True, True, True),
                    (False, True, False),
                ],
            )
        ):
            aged, history, restored = flags
            p = RequestProjection(
                key=("agent-local", str(i)),
                record_id=f"r-{i:05}",
                producer_kind="explicit",
                source_request_id=str(i),
                snapshot=snapshot if has_snapshot else None,
                source_state=state,
                current_confirmed=confirmed,
                evidence_class=evidence,
                last_confirmed_at=now,
                captured_at=now - timedelta(hours=2),
                aging_deadline=now - timedelta(hours=1),
                aged=aged,
                visibility=VisibilityState.HISTORY if history else VisibilityState.ACTIVE,
            )
            store._put_record(db, p, now)
            db.execute(
                "UPDATE records SET detail_retained=?,seen=?,snoozed_until=?,restored=? WHERE record_id=?",
                (detail, seen, snooze.isoformat() if snooze else None, restored, p.record_id),
            )
            expected.append(
                record_view(
                    store._stored(
                        db.execute(
                            "SELECT * FROM records WHERE record_id=?", (p.record_id,)
                        ).fetchone()
                    ),
                    now=now,
                )
            )
    predicates = {
        "attention": lambda r: r.needs_attention,
        "confirmed": lambda r: r.source_confirmed_pending,
        "unverified": lambda r: r.status_unverified,
        "history": lambda r: r.history,
        "recent_aged": lambda r: (
            r.status == PresentationStatus.OBSERVATION_AGED
            and r.aging_deadline is not None
            and now - timedelta(hours=24) <= r.aging_deadline <= now
        ),
    }
    totals = {
        name: sum(bool(predicate(r)) for r in expected) for name, predicate in predicates.items()
    }
    for filter, predicate in predicates.items():
        cursor, selected = None, []
        while True:
            page = store.inbox_page(now=now, filter=filter, cursor=cursor, limit=100)
            assert asdict(page.counts) == totals
            assert len(page.records) <= 100
            selected.extend(r.projection.record_id for r in page.records)
            if page.next_cursor is None:
                break
            assert page.next_cursor != cursor
            cursor = page.next_cursor
        assert selected == [r.record_id for r in expected if predicate(r)]


def test_recent_aged_exact_microsecond_bounds_and_get_never_ages(store, event_factory, now):
    deadlines = [
        now - timedelta(hours=24, microseconds=1),
        now - timedelta(hours=24),
        now,
        now + timedelta(microseconds=1),
    ]
    with store.transaction() as db:
        for i, deadline in enumerate(deadlines):
            p = RequestProjection(
                key=("agent-local", str(i)),
                record_id=f"r{i}",
                producer_kind="explicit",
                source_request_id=str(i),
                snapshot=event_factory().payload.snapshot,
                evidence_class=EvidenceClass.PRODUCER_REPORTED,
                captured_at=deadline - timedelta(hours=1),
                aging_deadline=deadline,
                aged=True,
                visibility=VisibilityState.HISTORY,
            )
            store._put_record(db, p, now)
    fresh = store.ingest(event_factory(event_id="fresh", request_id="fresh"), received_at=now)
    before = store.get_record(fresh.record_id)
    changes = store._db.total_changes
    page = store.inbox_page(now=now, filter="recent_aged")
    assert page.counts.recent_aged == 2
    assert [r.projection.record_id for r in page.records] == ["r1", "r2"]
    # Runtime aging is deliberately a separate writer responsibility.
    assert store.inbox_page(now=now + timedelta(hours=2)).counts.attention == 1
    assert store.get_record(fresh.record_id) == before
    assert store._db.total_changes == changes


@pytest.mark.parametrize("limit", [0, -1, 101, True, 1.0, "10", None])
def test_strict_page_limits(store, now, limit):
    for method, kwargs in [
        (store.inbox_page, {"now": now}),
        (store.alias_page, {}),
        (store.source_page, {}),
    ]:
        with pytest.raises(StorageError, match="^invalid_query_limit$"):
            method(limit=limit, **kwargs)


@pytest.mark.parametrize(
    "cursor",
    ["", "SECRET bad cursor", "x" * 1025, "WzEsImFsaWFzZXMiLHRydWVd", 1, True, {}, "bm90LWpzb24"],
)
def test_redacted_bad_cursors(store, now, cursor):
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        store.inbox_page(now=now, cursor=cursor)


def test_cursor_scope_and_unknown_filter_rejected(store, event_factory, now):
    for i in range(2):
        store.ingest(event_factory(event_id=str(i), request_id=str(i)), received_at=now)
    cursor = store.inbox_page(now=now, limit=1).next_cursor
    with pytest.raises(StorageError, match="invalid_query_cursor"):
        store.inbox_page(now=now, filter="history", cursor=cursor)
    for filter in ["SECRET SQL'", None, [], 1]:
        with pytest.raises(StorageError, match="^invalid_query_filter$"):
            store.inbox_page(now=now, filter=filter)


def test_alias_source_pages_and_offline_summary_are_read_only(
    store, native_capabilities, event_factory, now
):
    first = store.project_alias("first", local_path="PRIVATE_PATH")
    second = store.project_alias("second")
    assert store.alias_page(limit=1).aliases == (first,)
    assert store.alias_page(cursor=store.alias_page(limit=1).next_cursor).aliases == (second,)
    store.register_source(native_capabilities)
    assert not store.inbox_page(now=now).source_confirmed_supported
    store.register_source(native_capabilities, enabled=True, qualified=True, now=now)
    assert store.inbox_page(now=now).source_confirmed_supported
    receipt = store.ingest(event_factory(native=True, current=True, restored=True), received_at=now)
    before = store.get_record(receipt.record_id)
    changes = store._db.total_changes
    assert store.lookup_project_alias(first.identity) == first
    assert store.lookup_project_alias("identity:missing") is None
    assert store.lookup_project_alias("unknown").alias == "Unknown project"
    sources = store.source_page(limit=1)
    assert sources.total == 2 and len(sources.sources) == 1
    assert store.source_page(cursor=sources.next_cursor).sources[0].producer_id == "codex-native"
    summary = store.query_summary()
    assert summary.source_count == 2 and summary.enabled_source_count == 2
    assert summary.qualified_native_source_count == 1
    assert summary.last_capture_at == now and summary.integrity_ok is None
    assert "PRIVATE_PATH" not in repr(summary)
    offline = SQLiteStore.inspect_summary(store.path, verify_integrity=True)
    assert offline == replace(summary, integrity_ok=True)
    assert SQLiteStore.inspect_source_page(store.path, limit=1) == sources
    assert SQLiteStore.inspect_source_page(
        store.path, cursor=sources.next_cursor
    ) == store.source_page(cursor=sources.next_cursor)
    assert store.get_record(receipt.record_id) == before
    assert store._db.total_changes == changes
    path = store.path
    store.close()
    assert SQLiteStore.inspect_summary(path) == summary


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"limit": True}, "invalid_query_limit"),
        ({"cursor": "PRIVATE"}, "invalid_query_cursor"),
        ({"busy_timeout_ms": True}, "invalid_busy_timeout"),
    ],
)
def test_offline_source_page_rejects_invalid_query_before_access(tmp_path, kwargs, code):
    path = tmp_path / "PRIVATE-absent.db"
    with pytest.raises(StorageError, match=f"^{code}$"):
        SQLiteStore.inspect_source_page(path, **kwargs)
    assert not path.exists()


def test_large_compact_history_hydrates_only_requested_page(store, now, monkeypatch):
    count = 20_050
    compact = RequestProjection(
        key=("agent-local", "synthetic"),
        record_id="synthetic",
        producer_kind="explicit",
        source_request_id="synthetic",
        source_state=SourceState.AGENT_RESOLVED,
        visibility=VisibilityState.HISTORY,
    )
    body = PROJECTION.dump_json(compact).decode()
    with store.transaction() as db:
        db.executemany(
            "INSERT INTO records(record_key,producer_id,record_id,short_reference,projection,detail_retained,history_since) VALUES (?,'agent-local',?,?,?,0,?)",
            ((str(i), f"r{i:06}", f"R{i:07}", body, now.isoformat()) for i in range(count)),
        )
    original = store._stored
    calls = []

    def bounded(row):
        calls.append(row["record_id"])
        assert len(calls) <= 3
        return original(row)

    monkeypatch.setattr(store, "_stored", bounded)
    monkeypatch.setattr(store, "list_records", lambda **_: pytest.fail("unbounded public scan"))
    page = store.inbox_page(now=now, filter="history", limit=3)
    assert page.counts.history == count and len(page.records) == 3 and page.next_cursor
    assert len(calls) == 3


def test_offline_missing_database_never_created_and_errors_redacted(tmp_path):
    path = tmp_path / "PRIVATE-missing.db"
    with pytest.raises(StorageError, match="^database_inspection_failed$"):
        SQLiteStore.inspect_summary(path)
    assert not path.exists()


def test_page_totals_and_settings_share_snapshot_during_writer_commit(
    store, event_factory, now, monkeypatch
):
    receipt = store.ingest(event_factory(), received_at=now)
    original = store._stored
    old_settings = store.get_settings()

    def commit_during_hydration(row):
        store.update_settings(old_settings.revision, {"device_alias": "Changed later"}, now=now)
        store.set_record_metadata(receipt.record_id, seen=True, now=now)
        return original(row)

    monkeypatch.setattr(store, "_stored", commit_during_hydration)
    page = store.inbox_page(now=now)
    assert page.counts.attention == 1 and not page.records[0].seen
    assert page.settings == old_settings
    assert store.get_settings().revision == old_settings.revision + 1


def test_summary_is_bounded_allowlisted_and_capture_order_is_exact(store, event_factory, now):
    first = now.replace(microsecond=0)
    latest = first + timedelta(microseconds=1)
    # Capture chronology need not equal receive/event sequence chronology.
    store.ingest(
        event_factory(
            event_id="latest",
            request_id="latest",
            captured_at=latest,
            snapshot_changes={"title": "PRIVATE_BODY"},
        ),
        received_at=latest,
    )
    store.ingest(
        event_factory(event_id="older", request_id="older", captured_at=first), received_at=latest
    )
    with store.transaction() as db:
        db.execute("INSERT INTO diagnostics VALUES ('PRIVATE_CODE',7)")
        db.execute("INSERT INTO diagnostics VALUES ('event_payload_conflict',2)")
    value = store.query_summary()
    assert value.last_capture_at == latest
    assert value.diagnostic_counts == {"event_payload_conflict": 2}
    assert value.diagnostic_count == 9
    assert "PRIVATE" not in repr(value)


@pytest.mark.parametrize("timestamp", [None, "SECRET_BAD_TIMESTAMP", 17])
def test_bad_timestamps_are_redacted(store, timestamp):
    with pytest.raises(StorageError, match="^invalid_timestamp$"):
        store.inbox_page(now=timestamp)


@pytest.mark.parametrize("offline", [False, True])
@pytest.mark.parametrize(
    "producer_id",
    [
        "emoji-" + chr(0x1F600) * 100,
        "b" + chr(0x10FFFF) * 127,
        "a" + chr(0xFFFF) * 127,
        "nul\x00" + "a" * 124,
    ],
    ids=["review-reproduction", "max-astral", "max-bmp", "schema-valid-nul"],
)
def test_qry1_valid_unicode_source_cursor_traverses_all_pages(
    store, explicit_capabilities, producer_id, offline
):
    # Registration validates the existing <=128-character source schema first.
    store.register_source(explicit_capabilities.model_copy(update={"producer_id": producer_id}))
    store.register_source(
        explicit_capabilities.model_copy(
            update={"producer_id": producer_id + "z" if len(producer_id) < 128 else "z" * 128}
        )
    )
    read = (
        (lambda **kwargs: SQLiteStore.inspect_source_page(store.path, **kwargs))
        if offline
        else store.source_page
    )
    cursor, observed = None, []
    while True:
        page = read(limit=1, cursor=cursor)
        assert page.total == 3
        observed.extend(s.producer_id for s in page.sources)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert len(observed) == len(set(observed)) == 3
    assert producer_id in observed


@pytest.mark.parametrize(
    "scope,key,integer",
    [
        ("sources", chr(0x1F600) * 128, False),
        ("sources", '"\\\n' * 42 + "xy", False),
        ("inbox:attention", chr(0x10FFFF) * 256, False),
        ("inbox:confirmed", chr(0xFFFF) * 256, False),
        ("inbox:unverified", '"' * 256, False),
        ("inbox:history", "r" * 256, False),
        ("inbox:recent_aged", "r", False),
        ("aliases", 2**63 - 1, True),
        ("deliveries:all", 1, True),
        ("deliveries:" + "f" * 64, 2**63 - 1, True),
    ],
    ids=[
        "source-astral",
        "source-escaped",
        "inbox-astral",
        "inbox-bmp",
        "inbox-escaped",
        "inbox-ascii",
        "inbox-minimal",
        "alias-max",
        "delivery-min",
        "delivery-filter-max",
    ],
)
def test_qry1_all_cursor_domains_roundtrip_canonically(scope, key, integer):
    cursor = encode_cursor(scope, key)
    assert decode_cursor(cursor, scope, integer=integer) == key
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        decode_cursor(cursor, scope + "-other", integer=integer)
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        decode_cursor(cursor + "=", scope, integer=integer)


@pytest.mark.parametrize("bad_key", [chr(0xD800), chr(0xDFFF), "PRIVATE" + chr(0xD800)])
def test_qry2_surrogate_cursor_and_alias_are_redacted_before_database(
    store, now, monkeypatch, bad_key
):
    forged = (
        base64.urlsafe_b64encode(
            json.dumps([1, "inbox:attention", bad_key], separators=(",", ":")).encode("ascii")
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    monkeypatch.setattr(store, "read_snapshot", lambda: pytest.fail("invalid text reached SQLite"))
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        store.inbox_page(now=now, cursor=forged)
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        encode_cursor("inbox:attention", bad_key)
    with pytest.raises(StorageError, match="^invalid_project_identity$"):
        store.lookup_project_alias("identity:" + bad_key)


@pytest.mark.parametrize(
    "scope,key,integer",
    [
        ("sources", "a" * 129, False),
        ("inbox:attention", "a" * 257, False),
        ("sources", "", False),
        ("sources", 1, False),
        ("aliases", True, True),
        ("aliases", "1", True),
        ("aliases", 0, True),
        ("aliases", -1, True),
        ("deliveries:all", 2**63, True),
    ],
)
def test_qry_cursor_key_schema_and_types_are_enforced(scope, key, integer):
    forged = (
        base64.urlsafe_b64encode(json.dumps([1, scope, key], separators=(",", ":")).encode("ascii"))
        .rstrip(b"=")
        .decode("ascii")
    )
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        decode_cursor(forged, scope, integer=integer)
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        encode_cursor(scope, key)


@pytest.mark.parametrize(
    "scope,key,integer",
    [
        ("sources", chr(0x10FFFF) * 128, False),
        ("inbox:attention", chr(0x10FFFF) * 256, False),
        ("aliases", 2**63 - 1, True),
        ("deliveries:" + "a" * 64, 2**63 - 1, True),
    ],
)
def test_qry_wire_bound_rejects_before_decode(scope, key, integer, monkeypatch):
    longest = encode_cursor(scope, key)
    monkeypatch.setattr(
        base64, "b64decode", lambda *args, **kwargs: pytest.fail("oversized cursor was decoded")
    )
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        decode_cursor("A" * (len(longest) + 1), scope, integer=integer)


def test_qry_nested_malformed_cursor_has_redacted_error():
    malformed = ("[" * 1100 + "0" + "]" * 1100).encode("ascii")
    cursor = base64.urlsafe_b64encode(malformed).rstrip(b"=").decode("ascii")
    with pytest.raises(StorageError, match="^invalid_query_cursor$"):
        decode_cursor(cursor, "inbox:attention")
