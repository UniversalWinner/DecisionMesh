"""Bounded read models and SQL queries; no lifecycle or visibility mutation.

Counts inspect compact projection fields in SQLite, not Python request bodies.
Only the requested page is hydrated. Totals and page share one read snapshot;
keyset cursors identify ordering positions, not a frozen cross-request snapshot.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .capture import assert_owner_only
from .contracts import SourceCapabilities, utc_datetime
from .domain import SourceHealth
from .settings import Settings
from .storage import HEALTH, SCHEMA_VERSION, ProjectAlias, StorageError, StoredRecord, _stamp

MAX_PAGE_SIZE = 100
FILTERS = ("attention", "confirmed", "unverified", "history", "recent_aged")


@dataclass(frozen=True)
class InboxCounts:
    attention: int
    confirmed: int
    unverified: int
    history: int
    recent_aged: int


@dataclass(frozen=True)
class InboxPage:
    records: tuple[StoredRecord, ...]
    counts: InboxCounts
    next_cursor: str | None
    source_confirmed_supported: bool
    settings: Settings


@dataclass(frozen=True)
class AliasPage:
    aliases: tuple[ProjectAlias, ...]
    next_cursor: str | None
    total: int


@dataclass(frozen=True)
class SourceSummary:
    producer_id: str
    capabilities: SourceCapabilities
    enabled: bool
    qualified: bool
    health: SourceHealth | None


@dataclass(frozen=True)
class SourcePage:
    sources: tuple[SourceSummary, ...]
    next_cursor: str | None
    total: int


@dataclass(frozen=True)
class StoreSummary:
    source_count: int
    enabled_source_count: int
    qualified_native_source_count: int
    last_capture_at: datetime | None
    schema_version: int
    integrity_ok: bool | None
    diagnostic_counts: dict[str, int]
    diagnostic_count: int


def page_limit(limit):
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise StorageError("invalid_query_limit")


def time_key(value):
    """Exact microsecond ordering for both JSON 'Z' and SQLite '+00:00' stamps."""
    return utc_datetime(value).isoformat(timespec="microseconds") if value is not None else None


def configure_time(db):
    db.create_function("dm_time_key", 1, time_key, deterministic=True)


def valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _cursor_domain(scope):
    # Match the enrolled source schema (128 characters) and the existing record
    # query contract (256). SQLite ordinals/rowids use positive signed int64.
    if scope == "sources":
        return False, 128
    if scope in {"inbox:" + name for name in FILTERS}:
        return False, 256
    if scope == "aliases" or (
        type(scope) is str and re.fullmatch(r"deliveries:(all|[0-9a-f]{64})", scope)
    ):
        return True, 0
    raise ValueError


def _validate_cursor_key(key, scope, integer, max_characters):
    if integer:
        if type(key) is not int or not 1 <= key <= 2**63 - 1:
            raise ValueError
    elif (
        type(key) is not str
        or not 1 <= len(key) <= max_characters
        or not valid_utf8(key)
        or ("\x00" in key and scope != "sources")
    ):
        raise ValueError


def _cursor_max_length(scope, integer, max_characters):
    # ensure_ascii JSON takes at most 12 bytes per Unicode scalar (a surrogate
    # pair escape). Preserve existing canonical cursor bytes, including old ones.
    overhead = len(json.dumps([1, scope, 0 if integer else ""], separators=(",", ":")))
    raw_bytes = overhead + (len(str(2**63 - 1)) - 1 if integer else 12 * max_characters)
    return (4 * raw_bytes + 2) // 3  # exact unpadded base64 length upper bound


def encode_cursor(scope: str, key: int | str) -> str:
    try:
        integer, max_characters = _cursor_domain(scope)
        _validate_cursor_key(key, scope, integer, max_characters)
        raw = json.dumps([1, scope, key], separators=(",", ":")).encode("ascii")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    except (ValueError, TypeError, UnicodeError):
        raise StorageError("invalid_query_cursor") from None


def decode_cursor(cursor, scope, *, integer=False):
    try:
        expected_integer, max_characters = _cursor_domain(scope)
        if type(integer) is not bool or integer != expected_integer:
            raise ValueError
        if cursor is None:
            return 0 if integer else ""
        if (
            type(cursor) is not str
            or not 1 <= len(cursor) <= _cursor_max_length(scope, integer, max_characters)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor)
        ):
            raise ValueError
        decoded = json.loads(
            base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        )
        if (
            type(decoded) is not list
            or len(decoded) != 3
            or type(decoded[0]) is not int
            or decoded[:2] != [1, scope]
        ):
            raise ValueError
        key = decoded[2]
        _validate_cursor_key(key, scope, integer, max_characters)
        if encode_cursor(scope, key) != cursor:
            raise ValueError
        return key
    except (ValueError, TypeError, binascii.Error, UnicodeError, RecursionError):
        raise StorageError("invalid_query_cursor") from None


# Deliberately mirrors view.record_view/presentation_status precedence. Do not
# import the view layer into storage. Exhaustive predicate parity is tested.
INBOX_CTE = """
WITH facts AS (
    SELECT record_id, detail_retained, seen, snoozed_until, restored,
           json_extract(projection,'$.source_state') AS source_state,
           json_extract(projection,'$.visibility') AS visibility,
           json_extract(projection,'$.current_confirmed') AS current_confirmed,
           json_extract(projection,'$.aged') AS aged,
           json_extract(projection,'$.evidence_class') AS evidence_class,
           json_type(projection,'$.snapshot') NOT IN ('null') AS has_snapshot,
           dm_time_key(json_extract(projection,'$.aging_deadline')) AS aging_deadline
    FROM records
), statuses AS (
    SELECT *, source_state NOT IN ('pending','unverified') AS terminal,
           source_state NOT IN ('pending','unverified') OR visibility='history' AS history,
           CASE WHEN source_state NOT IN ('pending','unverified') THEN 'terminal'
                WHEN source_state='pending' AND current_confirmed THEN 'confirmed'
                WHEN source_state='pending' THEN 'last_known'
                WHEN restored THEN 'restored'
                WHEN aged OR visibility='history' THEN 'aged'
                WHEN evidence_class='producer_reported' THEN 'producer'
                WHEN evidence_class='prompt_confirmed' THEN 'prompt'
                ELSE 'gate' END AS status
    FROM facts
), classified AS (
    SELECT record_id, history, status='confirmed' AS confirmed,
           detail_retained AND has_snapshot AND NOT history
               AND (snoozed_until IS NULL OR dm_time_key(snoozed_until)<=dm_time_key(:now))
               AND (status='confirmed' OR (NOT seen AND status IN ('producer','prompt'))) AS attention,
           (status IN ('last_known','gate') OR NOT has_snapshot) AND NOT history AS unverified,
           status='aged' AND aging_deadline>=dm_time_key(:cutoff)
               AND aging_deadline<=dm_time_key(:now) AS recent_aged
    FROM statuses
)
"""

SUPPORTED_SQL = """SELECT EXISTS(
    SELECT 1 FROM sources WHERE enabled=1 AND qualified=1
    AND json_extract(capabilities,'$.producer_kind')='native'
    AND json_extract(capabilities,'$.authoritative_lifecycle')=1
    AND (json_extract(capabilities,'$.continuous_stream')=1
         OR json_extract(capabilities,'$.authoritative_current_snapshots')=1))"""


def inbox_page(store, *, now, filter="attention", cursor=None, limit=50):
    page_limit(limit)
    if type(filter) is not str or filter not in FILTERS:
        raise StorageError("invalid_query_filter")
    after = decode_cursor(cursor, "inbox:" + filter)
    stamp = _stamp(now)
    try:
        cutoff = _stamp(utc_datetime(now) - timedelta(hours=24))
    except (ValueError, TypeError, OverflowError):
        raise StorageError("invalid_timestamp") from None
    parameters = {"now": stamp, "cutoff": cutoff, "after": after, "limit": limit + 1}
    with store.read_snapshot() as db:
        configure_time(db)
        totals = db.execute(
            INBOX_CTE
            + "SELECT "
            + ",".join(f"coalesce(sum({name}),0) AS {name}" for name in FILTERS)
            + " FROM classified",
            parameters,
        ).fetchone()
        # Identifiers above/below come exclusively from fixed FILTERS, never input SQL.
        rows = db.execute(
            INBOX_CTE + f"SELECT r.* FROM records r JOIN classified c USING(record_id) "
            f"WHERE c.{filter} AND r.record_id>:after ORDER BY r.record_id LIMIT :limit",
            parameters,
        ).fetchall()
        return InboxPage(
            tuple(store._stored(row) for row in rows[:limit]),
            InboxCounts(**dict(totals)),
            encode_cursor("inbox:" + filter, rows[limit - 1]["record_id"])
            if len(rows) > limit
            else None,
            bool(db.execute(SUPPORTED_SQL).fetchone()[0]),
            store._settings(db),
        )


def lookup_project_alias(store, identity):
    """Read an already-normalized ProjectAlias.identity; never allocate an alias."""
    if (
        type(identity) is not str
        or not identity
        or len(identity) > 2057
        or "\x00" in identity
        or not valid_utf8(identity)
    ):
        raise StorageError("invalid_project_identity")
    if identity == "unknown":
        return ProjectAlias("unknown", "Unknown project", None)
    with store.read_snapshot() as db:
        row = db.execute(
            "SELECT identity,alias,local_path FROM aliases WHERE identity=?", (identity,)
        ).fetchone()
        return ProjectAlias(*row) if row else None


def alias_page(store, *, cursor=None, limit=50):
    page_limit(limit)
    after = decode_cursor(cursor, "aliases", integer=True)
    with store.read_snapshot() as db:
        total = db.execute("SELECT count(*) FROM aliases").fetchone()[0]
        rows = db.execute(
            "SELECT ordinal,identity,alias,local_path FROM aliases WHERE ordinal>? ORDER BY ordinal LIMIT ?",
            (after, limit + 1),
        ).fetchall()
        return AliasPage(
            tuple(ProjectAlias(r["identity"], r["alias"], r["local_path"]) for r in rows[:limit]),
            encode_cursor("aliases", rows[limit - 1]["ordinal"]) if len(rows) > limit else None,
            total,
        )


def source_page(store, *, cursor=None, limit=50):
    page_limit(limit)
    after = decode_cursor(cursor, "sources")
    with store.read_snapshot() as db:
        return _source_page(db, after=after, limit=limit)


def _source_page(db, *, after, limit):
    total = db.execute("SELECT count(*) FROM sources").fetchone()[0]
    rows = db.execute(
        "SELECT * FROM sources WHERE producer_id>? ORDER BY producer_id LIMIT ?",
        (after, limit + 1),
    ).fetchall()
    try:
        sources = tuple(
            SourceSummary(
                r["producer_id"],
                SourceCapabilities.model_validate_json(r["capabilities"]),
                bool(r["enabled"]),
                bool(r["qualified"]),
                HEALTH.validate_json(r["health"]) if r["health"] else None,
            )
            for r in rows[:limit]
        )
    except (ValueError, TypeError):
        raise StorageError("invalid_source_summary") from None
    return SourcePage(
        sources,
        encode_cursor("sources", rows[limit - 1]["producer_id"]) if len(rows) > limit else None,
        total,
    )


def summary(db, *, verify_integrity=False):
    configure_time(db)
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise StorageError("unsupported_query_schema")
    sources = db.execute(
        "SELECT count(*),coalesce(sum(enabled),0),coalesce(sum(qualified=1 AND json_extract(capabilities,'$.producer_kind')='native'),0) FROM sources"
    ).fetchone()
    capture = db.execute(
        "SELECT captured_at FROM events ORDER BY dm_time_key(captured_at) DESC LIMIT 1"
    ).fetchone()
    diagnostics = db.execute(
        "SELECT coalesce(sum(count),0),coalesce(sum(CASE WHEN code='event_payload_conflict' THEN count ELSE 0 END),0) FROM diagnostics"
    ).fetchone()
    integrity = None
    if verify_integrity:
        integrity = db.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
    return StoreSummary(
        *sources,
        utc_datetime(capture[0]) if capture else None,
        version,
        integrity,
        {"event_payload_conflict": diagnostics[1]},
        diagnostics[0],
    )


def inspect_summary(path, *, busy_timeout_ms=2000, verify_integrity=False):
    """Doctor-only reader: no store constructor, locks, migrations or restart."""
    if type(verify_integrity) is not bool:
        raise StorageError("invalid_integrity_flag")
    with _read_only(path, busy_timeout_ms=busy_timeout_ms) as db:
        return summary(db, verify_integrity=verify_integrity)


def inspect_source_page(path, *, cursor=None, limit=50, busy_timeout_ms=2000):
    page_limit(limit)
    after = decode_cursor(cursor, "sources")
    with _read_only(path, busy_timeout_ms=busy_timeout_ms) as db:
        if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise StorageError("unsupported_query_schema")
        return _source_page(db, after=after, limit=limit)


@contextmanager
def _read_only(path, *, busy_timeout_ms):
    if type(busy_timeout_ms) is not int or not 0 <= busy_timeout_ms <= 2000:
        raise StorageError("invalid_busy_timeout")
    db = None
    try:
        path = Path(path).absolute()
        assert_owner_only(path)
        db = sqlite3.connect(
            path.as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=busy_timeout_ms / 1000,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db
    except StorageError:
        raise
    except Exception:  # noqa: BLE001 - ACL/filesystem diagnostics may contain private paths.
        raise StorageError("database_inspection_failed") from None
    finally:
        if db is not None:
            db.close()
