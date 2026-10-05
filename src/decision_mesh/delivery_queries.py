"""Read-only bounded delivery evidence, without request bodies or provider IDs."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .capture import assert_owner_only
from .contracts import utc_datetime
from .delivery import DeliveryError
from .storage import StorageError
from .storage_queries import configure_time, decode_cursor, encode_cursor, page_limit, valid_utf8


@dataclass(frozen=True)
class DeliveryStatus:
    occurrence_id: str
    record_id: str
    short_reference: str
    status: str
    attempts: int
    duplicate_possible: bool
    retry_available: bool
    last_api_acceptance_at: datetime | None


@dataclass(frozen=True)
class DeliveryPage:
    occurrences: tuple[DeliveryStatus, ...]
    next_cursor: str | None
    total: int
    last_api_acceptance_at: datetime | None


@dataclass(frozen=True)
class DeliverySummary:
    total: int
    last_api_acceptance_at: datetime | None


def _summary(db):
    configure_time(db)
    present = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dm_delivery_occurrences'"
    ).fetchone()
    if not present:
        return DeliverySummary(0, None)
    total = db.execute("SELECT count(*) FROM dm_delivery_occurrences").fetchone()[0]
    accepted = db.execute(
        "SELECT max(dm_time_key(finished_at)) FROM dm_delivery_attempts WHERE outcome='accepted'"
    ).fetchone()[0]
    return DeliverySummary(total, utc_datetime(accepted) if accepted else None)


def occurrence_page(worker, *, record_id=None, cursor=None, limit=50):
    try:
        page_limit(limit)
        if record_id is not None and (
            type(record_id) is not str
            or not 1 <= len(record_id) <= 256
            or "\x00" in record_id
            or not valid_utf8(record_id)
        ):
            raise DeliveryError("invalid_record_id")
        scope = "deliveries:" + (
            hashlib.sha256(record_id.encode()).hexdigest() if record_id is not None else "all"
        )
        after = decode_cursor(cursor, scope, integer=True)
    except StorageError as exc:
        raise DeliveryError(str(exc)) from None
    with worker.store.read_snapshot() as db:
        configure_time(db)
        overview = _summary(db)
        where = " WHERE o.rowid>?" + (" AND o.record_id=?" if record_id is not None else "")
        params = (after, record_id, limit + 1) if record_id is not None else (after, limit + 1)
        rows = db.execute(
            "SELECT o.rowid AS cursor_id,o.occurrence_id,o.record_id,o.state,o.part_id,"
            "r.short_reference,p.state AS part_state,p.manual_pending,p.manual_target "
            "FROM dm_delivery_occurrences o JOIN records r USING(record_id) "
            "LEFT JOIN dm_delivery_parts p USING(part_id)" + where + " ORDER BY o.rowid LIMIT ?",
            params,
        ).fetchall()
        total = (
            overview.total
            if record_id is None
            else db.execute(
                "SELECT count(*) FROM dm_delivery_occurrences WHERE record_id=?", (record_id,)
            ).fetchone()[0]
        )
        selected = []
        for row in rows[:limit]:
            # Attempted membership never moves part. The existing (part_id,ordinal)
            # and (attempt_id,occurrence_id) indexes avoid lifetime history scans
            # for each row; membership ensures digest peers' retries aren't counted.
            history = db.execute(
                "SELECT count(*) AS attempts,coalesce(max(a.outcome IN ('accepted','outcome_unknown','started')),0) AS duplicate_possible,"
                "max(CASE WHEN a.outcome='accepted' THEN dm_time_key(a.finished_at) END) AS accepted "
                "FROM dm_delivery_attempts a WHERE a.part_id=? AND EXISTS ("
                "SELECT 1 FROM dm_delivery_attempt_members m WHERE m.attempt_id=a.attempt_id AND m.occurrence_id=?)",
                (row["part_id"], row["occurrence_id"]),
            ).fetchone()
            state = row["state"]
            scheduled_member = row["manual_target"] in {None, row["occurrence_id"]}
            if state not in {"cancelled", "suppressed"} and scheduled_member:
                state = {"ready": "queued", "retry": "retry", "inflight": "inflight"}.get(
                    row["part_state"], state
                )
            retry_available = (
                row["state"] not in {"cancelled", "suppressed", "inflight"}
                and row["part_id"] is not None
                and not row["manual_pending"]
                and row["part_state"] not in {"ready", "retry", "inflight"}
            )
            selected.append(
                DeliveryStatus(
                    row["occurrence_id"],
                    row["record_id"],
                    row["short_reference"],
                    state,
                    history["attempts"],
                    bool(history["duplicate_possible"]),
                    bool(retry_available),
                    utc_datetime(history["accepted"]) if history["accepted"] else None,
                )
            )
        return DeliveryPage(
            tuple(selected),
            encode_cursor(scope, rows[limit - 1]["cursor_id"]) if len(rows) > limit else None,
            total,
            overview.last_api_acceptance_at,
        )


def inspect_summary(path, *, busy_timeout_ms=2000):
    if type(busy_timeout_ms) is not int or not 0 <= busy_timeout_ms <= 2000:
        raise DeliveryError("invalid_busy_timeout")
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
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        return _summary(db)
    except Exception:  # noqa: BLE001 - never surface ACL paths or database content.
        raise DeliveryError("database_inspection_failed") from None
    finally:
        if db is not None:
            db.close()
