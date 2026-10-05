"""One-writer SQLite store. Network I/O must never run inside transaction().

The reducer receives indexed slices, not an ever-growing replay log. Compact
identities survive detail pruning. The source enrollment API is for controlled
application setup only, never an event/HTTP input or capability inference.
"""

from __future__ import annotations

import json
import ntpath
import os
import secrets
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from itertools import combinations
from pathlib import Path

from pydantic import TypeAdapter

from .capture import assert_owner_only, atomic_write_owner_only, ensure_spool_dir, owner_file_lock
from .contracts import (
    Event,
    EvidenceClass,
    HealthEvent,
    SourceCapabilities,
    SourceState,
    canonical_event_bytes,
    event_digest,
    utc_datetime,
    validate_event,
)
from .domain import (
    EventReceipt,
    MeshState,
    RequestProjection,
    ResultCategory,
    RevisionReceipt,
    SessionEnd,
    SourceHealth,
    VisibilityState,
    age_state,
    disconnect_source,
    reduce_event,
)
from .settings import (
    CapturePolicy,
    Settings,
    SettingsConflict,
    SettingsError,
    revised_settings,
    validate_alias,
)

SCHEMA_VERSION = 2
SHORTREF_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PROJECTION = TypeAdapter(RequestProjection)
HEALTH = TypeAdapter(SourceHealth)
SESSION_END = TypeAdapter(SessionEnd)

MIGRATIONS = {
    1: (
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "CREATE TABLE schema_versions (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
        "CREATE TABLE extensions (name TEXT PRIMARY KEY, version INTEGER NOT NULL)",
        (
            "CREATE TABLE sources (producer_id TEXT PRIMARY KEY, capabilities TEXT NOT NULL, "
            "enabled INTEGER NOT NULL, qualified INTEGER NOT NULL, health TEXT)"
        ),
        "CREATE TABLE settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL)",
        "CREATE TABLE policies (policy_ref TEXT PRIMARY KEY, body TEXT NOT NULL)",
        (
            "CREATE TABLE session_ends (producer_id TEXT NOT NULL, scope_key TEXT NOT NULL, "
            "body TEXT NOT NULL, PRIMARY KEY(producer_id,scope_key))"
        ),
        (
            "CREATE TABLE records (record_key TEXT PRIMARY KEY, producer_id TEXT NOT NULL, "
            "record_id TEXT NOT NULL UNIQUE, short_reference TEXT NOT NULL UNIQUE, projection TEXT NOT NULL, "
            "detail_retained INTEGER NOT NULL, history_since TEXT, seen INTEGER NOT NULL DEFAULT 0, "
            "snoozed_until TEXT, suppressed INTEGER NOT NULL DEFAULT 0, restored INTEGER NOT NULL DEFAULT 0)"
        ),
        "CREATE INDEX records_source ON records(producer_id)",
        "CREATE INDEX records_prunable ON records(detail_retained,history_since)",
        (
            "CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, producer_id TEXT NOT NULL, "
            "event_id TEXT NOT NULL, digest TEXT NOT NULL, received_at TEXT NOT NULL, captured_at TEXT NOT NULL, "
            "category TEXT NOT NULL, flags TEXT NOT NULL, record_key TEXT, UNIQUE(producer_id,event_id))"
        ),
        "CREATE INDEX events_record ON events(record_key,sequence)",
        (
            "CREATE TABLE event_details (sequence INTEGER PRIMARY KEY REFERENCES events(sequence), "
            "record_key TEXT, body TEXT NOT NULL)"
        ),
        "CREATE INDEX details_record ON event_details(record_key)",
        (
            "CREATE TABLE revisions (record_key TEXT NOT NULL, stream TEXT NOT NULL, revision INTEGER NOT NULL, "
            "digest TEXT NOT NULL, PRIMARY KEY(record_key,stream,revision))"
        ),
        "CREATE TABLE diagnostics (code TEXT PRIMARY KEY, count INTEGER NOT NULL)",
        (
            "CREATE TABLE eligibility (sequence INTEGER PRIMARY KEY REFERENCES events(sequence), "
            "record_id TEXT NOT NULL, revision INTEGER NOT NULL, kind TEXT NOT NULL, "
            "policy_ref TEXT, destination_generation INTEGER, recovery_epoch TEXT NOT NULL)"
        ),
        "CREATE INDEX eligibility_record ON eligibility(record_id,sequence)",
        "CREATE INDEX eligibility_kind ON eligibility(kind,sequence)",
        (
            "CREATE TABLE aliases (identity TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE, "
            "alias TEXT NOT NULL, local_path TEXT)"
        ),
    ),
    2: (
        "ALTER TABLE records ADD COLUMN reducer_retained INTEGER NOT NULL DEFAULT 0",
        (
            "UPDATE records SET reducer_retained=1 WHERE detail_retained=1 OR "
            "(json_extract(projection,'$.snapshot_digest') IS NULL AND "
            "json_extract(projection,'$.source_state') IN ('pending','unverified'))"
        ),
        "CREATE INDEX records_reducer ON records(reducer_retained,producer_id)",
        # In v1 an audit-only row could store a prospective key. A prior ordinary
        # event with that key proves the record already existed at this commit;
        # otherwise preserve the original absence, even if a later record exists.
        (
            "UPDATE events SET record_key=NULL WHERE "
            "EXISTS (SELECT 1 FROM json_each(events.flags) WHERE value='pre_restore_audit_only') "
            "AND NOT EXISTS (SELECT 1 FROM events AS prior WHERE prior.record_key=events.record_key "
            "AND prior.sequence<events.sequence AND NOT EXISTS "
            "(SELECT 1 FROM json_each(prior.flags) WHERE value='pre_restore_audit_only'))"
        ),
        (
            "UPDATE event_details SET record_key=(SELECT record_key FROM events "
            "WHERE events.sequence=event_details.sequence)"
        ),
    ),
}


class StorageError(RuntimeError):
    """Redacted diagnostic code, never a validation body or event payload."""


class CapacityError(StorageError):
    pass


@dataclass(frozen=True)
class IngestReceipt:
    sequence: int
    producer_id: str
    event_id: str
    received_at: datetime
    category: ResultCategory
    flags: tuple[str, ...]
    record_id: str | None
    short_reference: str | None
    replayed: bool = False


@dataclass(frozen=True)
class StoredRecord:
    projection: RequestProjection
    short_reference: str
    detail_retained: bool
    seen: bool
    snoozed_until: datetime | None
    suppressed: bool
    restored: bool


@dataclass(frozen=True)
class Eligibility:
    sequence: int
    record_id: str
    revision: int
    kind: str
    policy_ref: str | None
    destination_generation: int | None
    recovery_epoch: str


@dataclass(frozen=True)
class ProjectAlias:
    identity: str
    alias: str
    local_path: str | None


@dataclass(frozen=True)
class RecoveryState:
    epoch: str
    restored_at: datetime | None


def _stamp(value: datetime) -> str:
    try:
        return utc_datetime(value).isoformat()
    except (ValueError, TypeError, OverflowError):
        raise StorageError("invalid_timestamp") from None


def _key(value: tuple) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _dump_projection(value: RequestProjection) -> str:
    return PROJECTION.dump_json(value).decode("utf-8")


def _load_projection(value: str) -> RequestProjection:
    try:
        return PROJECTION.validate_json(value)
    except (ValueError, TypeError, OverflowError):
        raise StorageError("invalid_projection") from None


class SQLiteStore:
    def __init__(
        self,
        path: Path | str,
        *,
        detail_limit: int = 10_000,
        busy_timeout_ms: int = 2_000,
        now: datetime | None = None,
        fault_hook: Callable[[str], None] | None = None,
        reference_factory: Callable[[], str] | None = None,
    ):
        if type(detail_limit) is not int or not 1 <= detail_limit <= 10_000:
            raise StorageError("invalid_detail_limit")
        if type(busy_timeout_ms) is not int or not 0 <= busy_timeout_ms <= 2_000:
            raise StorageError("invalid_busy_timeout")
        self.path = Path(path).absolute()
        self.detail_limit = detail_limit
        self.busy_timeout_ms = busy_timeout_ms
        self._mutex = threading.RLock()
        self._fault_hook = fault_hook
        self._reference_factory = reference_factory or (
            lambda: "".join(secrets.choice(SHORTREF_ALPHABET) for _ in range(8))
        )
        self._db = None
        self._writer_lock = None
        try:
            ensure_spool_dir(self.path.parent)
            self._writer_lock = owner_file_lock(
                self.path.with_name(self.path.name + ".writer.lock"), timeout=busy_timeout_ms / 1000
            )
            self._writer_lock.__enter__()
            if self.path.exists():
                assert_owner_only(self.path)
            else:
                atomic_write_owner_only(self.path, b"")
            self._db = sqlite3.connect(
                self.path,
                timeout=busy_timeout_ms / 1000,
                isolation_level=None,
                check_same_thread=False,
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA trusted_schema=OFF")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StorageError("newer_schema")
            if self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise StorageError("database_invalid")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._migrate(version, now or datetime.now(UTC))
            self._validate_schema()
            self._restart(now or datetime.now(UTC))
        except BaseException as exc:
            self.close()
            if isinstance(exc, StorageError):
                raise
            if isinstance(exc, Exception):
                raise StorageError("store_open_failed") from None
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        with self._mutex:
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._writer_lock is not None:
                self._writer_lock.__exit__(None, None, None)
                self._writer_lock = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialized short DB-only write seam for the delivery worker.

        Never perform network I/O here. Nested transactions are rejected. Public
        read methods use separate snapshots and must not be used to inspect an
        uncommitted write; use the yielded connection for dependent reads.
        """
        with self._mutex:
            if self._db is None:
                raise StorageError("store_closed")
            if self._db.in_transaction:
                raise StorageError("nested_transaction")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                yield self._db
                self._db.execute("COMMIT")
            except BaseException as exc:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                if isinstance(exc, sqlite3.Error):
                    raise StorageError("database_transaction_failed") from None
                raise

    @contextmanager
    def read_snapshot(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=ro",
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            yield connection
        except sqlite3.Error:
            raise StorageError("database_read_failed") from None
        finally:
            if connection is not None:
                connection.close()

    def _fault(self, point: str) -> None:
        if self._fault_hook:
            self._fault_hook(point)

    def _migrate(self, version: int, now: datetime) -> None:
        if version == SCHEMA_VERSION:
            return
        if version:
            self.backup(
                self.path.with_name(
                    self.path.name + f".pre-v{SCHEMA_VERSION}-{uuid.uuid4().hex}.bak"
                )
            )
        with self.transaction() as db:
            for target in range(version + 1, SCHEMA_VERSION + 1):
                for statement in MIGRATIONS[target]:
                    db.execute(statement)
                db.execute("INSERT INTO schema_versions VALUES (?,?)", (target, _stamp(now)))
                db.execute(f"PRAGMA user_version={target}")
                self._fault("migration_applied")
            if version == 0:
                db.execute("INSERT INTO settings VALUES (1,?)", (Settings().model_dump_json(),))
                db.execute("INSERT INTO metadata VALUES ('recovery_epoch',?)", (uuid.uuid4().hex,))
                self._new_policy(db, Settings(), now)
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise StorageError("migration_integrity_failed")

    def _validate_schema(self) -> None:
        try:
            self._settings(self._db)
            self._db.execute(
                "SELECT projection, short_reference, restored, reducer_retained FROM records LIMIT 0"
            )
            self._db.execute("SELECT sequence, recovery_epoch FROM eligibility LIMIT 0")
            if self._db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise StorageError("database_invalid")
            if self._meta(self._db, "recovery_epoch") is None:
                raise StorageError("database_invalid")
        except (ValueError, TypeError, sqlite3.Error):
            raise StorageError("database_invalid") from None

    @staticmethod
    def _meta(db, key: str) -> str | None:
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    @staticmethod
    def _settings(db) -> Settings:
        return Settings.model_validate_json(
            db.execute("SELECT body FROM settings WHERE singleton=1").fetchone()[0]
        )

    def get_settings(self) -> Settings:
        with self.read_snapshot() as db:
            return self._settings(db)

    def recovery_state(self) -> RecoveryState:
        with self.read_snapshot() as db:
            restored = self._meta(db, "restore_time")
            return RecoveryState(
                self._meta(db, "recovery_epoch"), utc_datetime(restored) if restored else None
            )

    def _new_policy(self, db, settings: Settings, now: datetime) -> CapturePolicy:
        policy = CapturePolicy(
            policy_ref="policy-" + uuid.uuid4().hex,
            settings_revision=settings.revision,
            destination_generation=settings.destination_generation,
            channel_active=settings.channel_active,
            destination=settings.destination,
            disclosure_fields=settings.disclosure_fields,
            created_at=now,
        )
        db.execute(
            "INSERT INTO policies VALUES (?,?)", (policy.policy_ref, policy.model_dump_json())
        )
        db.execute(
            "INSERT OR REPLACE INTO metadata VALUES ('current_policy',?)", (policy.policy_ref,)
        )
        return policy

    def update_settings(self, expected_revision: int, changes: dict, *, now: datetime) -> Settings:
        with self.transaction() as db:
            old = self._settings(db)
            if type(expected_revision) is not int or old.revision != expected_revision:
                raise SettingsConflict("stale_settings_revision")
            updated = revised_settings(old, changes)
            db.execute("UPDATE settings SET body=? WHERE singleton=1", (updated.model_dump_json(),))
            if updated.destination_generation != old.destination_generation:
                db.execute(
                    "UPDATE eligibility SET kind='cancelled' WHERE kind IN ('candidate','historical_summary')"
                )
            if (
                updated.destination_generation != old.destination_generation
                or updated.disclosure_fields != old.disclosure_fields
            ):
                self._new_policy(db, updated, now)
            return updated

    @staticmethod
    def _policy(db, reference: str | None) -> CapturePolicy | None:
        if reference is None:
            return None
        row = db.execute("SELECT body FROM policies WHERE policy_ref=?", (reference,)).fetchone()
        return CapturePolicy.model_validate_json(row[0]) if row else None

    def get_policy(self, reference: str | None) -> CapturePolicy | None:
        with self.read_snapshot() as db:
            return self._policy(db, reference)

    def current_policy(self) -> CapturePolicy:
        with self.read_snapshot() as db:
            return self._policy(db, self._meta(db, "current_policy"))

    def publish_capture_policy(self, path: Path | str) -> None:
        # Hold the writer mutex until atomic publication so settings updates cannot
        # publish out of order through this store instance. Crash-stale snapshots
        # are harmless because ingest revalidates generation against the database.
        with self._mutex:
            policy = self.current_policy()
            body = {
                "schema_version": 1,
                "capture_policy_ref": policy.policy_ref,
                "channel_active": policy.channel_active,
            }
            atomic_write_owner_only(path, json.dumps(body).encode(), max_bytes=4096)

    def register_source(
        self,
        capabilities: SourceCapabilities,
        *,
        enabled: bool | None = None,
        qualified: bool = False,
        now: datetime | None = None,
    ) -> None:
        """Controlled setup API. Native manifests remain disabled/unverified by default."""
        try:
            capabilities = SourceCapabilities.model_validate_json(capabilities.model_dump_json())
        except (ValueError, AttributeError, TypeError):
            raise StorageError("invalid_source_manifest") from None
        if enabled is None:
            enabled = capabilities.producer_kind == "explicit"
        if type(enabled) is not bool or type(qualified) is not bool:
            raise StorageError("invalid_source_registration")
        if enabled and capabilities.producer_kind == "native" and not qualified:
            raise StorageError("native_source_unverified")
        with self.transaction() as db:
            prior = db.execute(
                "SELECT capabilities,enabled,qualified FROM sources WHERE producer_id=?",
                (capabilities.producer_id,),
            ).fetchone()
            serialized = capabilities.model_dump_json()
            if prior and tuple(prior) != (serialized, int(enabled), int(qualified)):
                self._disconnect(db, capabilities.producer_id, now or datetime.now(UTC))
            db.execute(
                "INSERT INTO sources(producer_id,capabilities,enabled,qualified) VALUES (?,?,?,?) "
                "ON CONFLICT(producer_id) DO UPDATE SET capabilities=excluded.capabilities,enabled=excluded.enabled,qualified=excluded.qualified",
                (capabilities.producer_id, serialized, int(enabled), int(qualified)),
            )

    def source_registration(self, producer_id: str) -> dict | None:
        with self.read_snapshot() as db:
            row = db.execute("SELECT * FROM sources WHERE producer_id=?", (producer_id,)).fetchone()
            return dict(row) if row else None

    def _slice(self, db, event: Event) -> MeshState:
        key = (
            (event.producer_id, event.source_request_id)
            if event.source_request_id is not None
            else (event.producer_id, "", event.event_id)
        )
        records = tuple(
            _load_projection(r[0])
            for r in db.execute("SELECT projection FROM records WHERE record_key=?", (_key(key),))
        )
        # Source health events and native gaps can demote other source records.
        # Live execution orphans have no snapshot but still need continuity
        # updates. The indexed retained reducer set is bounded separately from
        # snapshot presence; compact historical tombstones are not loaded.
        if isinstance(event, HealthEvent) or (
            event.source_context.producer_kind == "native"
            and event.revision is not None
            and event.revision
            > (
                getattr(
                    records[0],
                    "execution_revision"
                    if event.event_kind == "execution.updated"
                    else "request_revision",
                )
                if records
                else 0
            )
            + 1
        ):
            records = tuple(
                _load_projection(r[0])
                for r in db.execute(
                    "SELECT projection FROM records WHERE producer_id=? AND reducer_retained=1",
                    (event.producer_id,),
                )
            )
            target = db.execute(
                "SELECT projection FROM records WHERE record_key=? AND reducer_retained=0",
                (_key(key),),
            ).fetchone()
            if target:
                records += (_load_projection(target[0]),)
        source_row = db.execute(
            "SELECT health FROM sources WHERE producer_id=?", (event.producer_id,)
        ).fetchone()
        sources = (HEALTH.validate_json(source_row[0]),) if source_row and source_row[0] else ()
        event_row = db.execute(
            "SELECT digest,received_at FROM events WHERE producer_id=? AND event_id=?",
            (event.producer_id, event.event_id),
        ).fetchone()
        events = (
            (
                EventReceipt(
                    (event.producer_id, event.event_id), event_row[0], utc_datetime(event_row[1])
                ),
            )
            if event_row
            else ()
        )
        revisions = ()
        if event.revision is not None:
            stream = "execution" if event.event_kind == "execution.updated" else "request"
            revision_row = db.execute(
                "SELECT digest FROM revisions WHERE record_key=? AND stream=? AND revision=?",
                (_key(key), stream, event.revision),
            ).fetchone()
            if revision_row:
                revisions = (RevisionReceipt(key, stream, event.revision, revision_row[0]),)
        # At most fifteen scope-key lookups; no scan of a source's growing
        # session history. Full known identity scope is checked again by reducer.
        pairs = sorted(
            (name, getattr(event.source_context, name))
            for name in ("thread_id", "turn_id", "session_id", "source_instance_id")
            if getattr(event.source_context, name) is not None
        )
        scope_keys = [
            _key(scope)
            for length in range(1, len(pairs) + 1)
            for scope in combinations(pairs, length)
        ]
        ends = ()
        if scope_keys:
            placeholders = ",".join("?" for _ in scope_keys)
            ends = tuple(
                SESSION_END.validate_json(row[0])
                for row in db.execute(
                    f"SELECT body FROM session_ends WHERE producer_id=? AND scope_key IN ({placeholders})",
                    (event.producer_id, *scope_keys),
                )
            )
        return MeshState(
            records=records, events=events, revisions=revisions, sources=sources, session_ends=ends
        )

    def _reference(self, db) -> str:
        for _ in range(128):
            value = self._reference_factory()
            if len(value) != 8 or any(c not in SHORTREF_ALPHABET for c in value):
                raise StorageError("invalid_short_reference")
            if (
                db.execute("SELECT 1 FROM records WHERE short_reference=?", (value,)).fetchone()
                is None
            ):
                return value
        raise StorageError("short_reference_collision_limit")

    def _put_record(self, db, record: RequestProjection, now: datetime) -> None:
        key = _key(record.key)
        old = db.execute(
            "SELECT short_reference,history_since,detail_retained FROM records WHERE record_key=?",
            (key,),
        ).fetchone()
        history = record.visibility == VisibilityState.HISTORY
        history_since = (old[1] if old and old[1] else _stamp(now)) if history else None
        detail_retained = record.snapshot is not None
        reducer_retained = detail_retained or (
            record.snapshot_digest is None and not record.terminal
        )
        reference = old[0] if old else self._reference(db)
        db.execute(
            "INSERT INTO records(record_key,producer_id,record_id,short_reference,projection,detail_retained,history_since,reducer_retained) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(record_key) DO UPDATE SET projection=excluded.projection,detail_retained=excluded.detail_retained,history_since=excluded.history_since,reducer_retained=excluded.reducer_retained",
            (
                key,
                record.key[0],
                record.record_id,
                reference,
                _dump_projection(record),
                int(detail_retained),
                history_since,
                int(reducer_retained),
            ),
        )

    def ingest(
        self,
        raw: bytes | str | dict | Event,
        *,
        received_at: datetime,
        expected_producer_id: str | None = None,
    ) -> IngestReceipt:
        try:
            stamp = utc_datetime(received_at)
            event = validate_event(
                canonical_event_bytes(raw) if hasattr(raw, "model_dump") else raw, now=stamp
            )
        except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
            raise StorageError("invalid_event") from None
        if expected_producer_id is not None and event.producer_id != expected_producer_id:
            raise StorageError("source_namespace_mismatch")
        with self.transaction() as db:
            source = db.execute(
                "SELECT * FROM sources WHERE producer_id=?", (event.producer_id,)
            ).fetchone()
            if source is None or not source["enabled"]:
                raise StorageError("source_not_enrolled_or_disabled")
            capabilities = SourceCapabilities.model_validate_json(source["capabilities"])
            prior = db.execute(
                "SELECT * FROM events WHERE producer_id=? AND event_id=?",
                (event.producer_id, event.event_id),
            ).fetchone()
            if prior:
                if prior["digest"] == event_digest(event):
                    return self._receipt(db, prior, replayed=True)
                self._diagnostic(db, "event_payload_conflict")
                return replace(
                    self._receipt(db, prior),
                    category=ResultCategory.CONFLICT,
                    flags=("event_payload_conflict",),
                    replayed=True,
                )
            state = self._slice(db, event)
            result = reduce_event(state, event, received_at=stamp, capabilities=capabilities)
            restore_time = self._meta(db, "restore_time")
            audit_only = bool(restore_time and event.captured_at <= utc_datetime(restore_time))
            flags = result.flags + (("pre_restore_audit_only",) if audit_only else ())
            key = _key(result.record.key) if result.record else None
            cursor = db.execute(
                "INSERT INTO events(producer_id,event_id,digest,received_at,captured_at,category,flags,record_key) VALUES (?,?,?,?,?,?,?,?)",
                (
                    event.producer_id,
                    event.event_id,
                    event_digest(event),
                    _stamp(stamp),
                    _stamp(event.captured_at),
                    result.category.value,
                    json.dumps(flags),
                    key,
                ),
            )
            sequence = cursor.lastrowid
            self._fault("event_written")
            for receipt in result.state.revisions:
                db.execute(
                    "INSERT OR IGNORE INTO revisions VALUES (?,?,?,?)",
                    (_key(receipt.key), receipt.stream, receipt.revision, receipt.digest),
                )
            if not audit_only:
                for record in result.state.records:
                    if record not in state.records:
                        previous = state.record(record.key)
                        if (
                            record == result.record
                            and "non_substantive_revision" in flags
                            and previous is not None
                            and previous.snapshot is None
                            and previous.snapshot_digest is not None
                        ):
                            # Reducer snapshots describe the incoming evidence;
                            # replay must not renew already-pruned sensitive detail.
                            record = replace(record, snapshot=None)
                        self._put_record(db, record, stamp)
                        self._recheck_record_eligibility(db, record)
                        if (
                            result.category == ResultCategory.APPLY
                            and record == result.record
                            and "non_substantive_revision" not in flags
                        ):
                            db.execute(
                                "UPDATE records SET restored=0 WHERE record_id=?",
                                (record.record_id,),
                            )
                for health in result.state.sources:
                    db.execute(
                        "UPDATE sources SET health=? WHERE producer_id=?",
                        (HEALTH.dump_json(health).decode(), health.producer_id),
                    )
                for end in result.state.session_ends:
                    db.execute(
                        "INSERT INTO session_ends VALUES (?,?,?) ON CONFLICT(producer_id,scope_key) DO UPDATE SET body=excluded.body",
                        (end.producer_id, _key(end.scope), SESSION_END.dump_json(end).decode()),
                    )
            self._fault("projection_written")
            if (
                result.record
                and result.category == ResultCategory.APPLY
                and event.event_kind not in {"source.health", "execution.updated"}
                and "non_substantive_revision" not in flags
            ):
                record = result.record
                policy = self._policy(db, record.capture_policy_ref)
                settings = self._settings(db)
                kind = (
                    "audit_only"
                    if audit_only
                    else self._eligibility_kind(record, policy, settings, event.captured_at)
                )
                metadata = db.execute(
                    "SELECT suppressed FROM records WHERE record_id=?", (record.record_id,)
                ).fetchone()
                if metadata and metadata[0] and not audit_only:
                    kind = "cancelled"
                db.execute(
                    "INSERT INTO eligibility VALUES (?,?,?,?,?,?,?)",
                    (
                        sequence,
                        record.record_id,
                        record.request_revision,
                        kind,
                        record.capture_policy_ref,
                        policy.destination_generation if policy else None,
                        self._meta(db, "recovery_epoch"),
                    ),
                )
            self._fault("eligibility_written")
            association = db.execute(
                "SELECT record_key,reducer_retained FROM records WHERE record_key=?", (key,)
            ).fetchone()
            # The immutable key pins either the original record association or
            # its absence. Later material ingestion cannot enrich an old receipt.
            committed_key = association[0] if association else None
            db.execute("UPDATE events SET record_key=? WHERE sequence=?", (committed_key, sequence))
            if association is None or association[1]:
                db.execute(
                    "INSERT INTO event_details VALUES (?,?,?)",
                    (sequence, committed_key, canonical_event_bytes(event).decode()),
                )
            self._prune(db, stamp)
            row = db.execute("SELECT * FROM events WHERE sequence=?", (sequence,)).fetchone()
            receipt = self._receipt(db, row)
        self._fault("committed")
        return receipt

    @staticmethod
    def _diagnostic(db, code: str) -> None:
        db.execute(
            "INSERT INTO diagnostics VALUES (?,1) ON CONFLICT(code) DO UPDATE SET count=count+1",
            (code,),
        )

    @staticmethod
    def _eligibility_kind(record, policy, settings, captured_at) -> str:
        if record.terminal:
            return "cancelled"
        if policy is None or not policy.permits_route(settings) or policy.created_at > captured_at:
            return "local_only"
        if record.evidence_class == EvidenceClass.GATE_OBSERVED:
            return "local_only"
        if record.source_state == SourceState.PENDING and not record.current_confirmed:
            return "local_only"
        return "historical_summary" if record.aged else "candidate"

    @staticmethod
    def _recheck_record_eligibility(db, record: RequestProjection) -> None:
        if record.terminal:
            db.execute(
                "UPDATE eligibility SET kind='cancelled' WHERE record_id=? AND kind IN ('candidate','historical_summary')",
                (record.record_id,),
            )
        elif record.aged:
            db.execute(
                "UPDATE eligibility SET kind='historical_summary' WHERE record_id=? AND kind='candidate'",
                (record.record_id,),
            )

    @staticmethod
    def _receipt(db, row, *, replayed=False) -> IngestReceipt:
        record = db.execute(
            "SELECT record_id,short_reference FROM records WHERE record_key=?", (row["record_key"],)
        ).fetchone()
        return IngestReceipt(
            row["sequence"],
            row["producer_id"],
            row["event_id"],
            utc_datetime(row["received_at"]),
            ResultCategory(row["category"]),
            tuple(json.loads(row["flags"])),
            record[0] if record else None,
            record[1] if record else None,
            replayed,
        )

    @staticmethod
    def _stored(row) -> StoredRecord:
        return StoredRecord(
            _load_projection(row["projection"]),
            row["short_reference"],
            bool(row["detail_retained"]),
            bool(row["seen"]),
            utc_datetime(row["snoozed_until"]) if row["snoozed_until"] else None,
            bool(row["suppressed"]),
            bool(row["restored"]),
        )

    def get_record(self, record_id: str) -> StoredRecord | None:
        with self.read_snapshot() as db:
            row = db.execute("SELECT * FROM records WHERE record_id=?", (record_id,)).fetchone()
            return self._stored(row) if row else None

    def lookup_reference(self, reference: str) -> StoredRecord | None:
        with self.read_snapshot() as db:
            row = db.execute(
                "SELECT * FROM records WHERE short_reference=?", (reference.upper(),)
            ).fetchone()
            return self._stored(row) if row else None

    def list_records(
        self, *, limit: int = 100, after_record_id: str = ""
    ) -> tuple[StoredRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise StorageError("invalid_query_limit")
        with self.read_snapshot() as db:
            return tuple(
                self._stored(row)
                for row in db.execute(
                    "SELECT * FROM records WHERE record_id>? ORDER BY record_id LIMIT ?",
                    (after_record_id, limit),
                )
            )

    def inbox_page(self, *, now: datetime, filter="attention", cursor=None, limit=50):
        """Read-only page and authoritative totals; never advances aging."""
        from .storage_queries import inbox_page

        return inbox_page(self, now=now, filter=filter, cursor=cursor, limit=limit)

    def lookup_project_alias(self, identity: str) -> ProjectAlias | None:
        """Look up the normalized identity returned by project_alias without writes."""
        from .storage_queries import lookup_project_alias

        return lookup_project_alias(self, identity)

    def alias_page(self, *, cursor=None, limit=50):
        from .storage_queries import alias_page

        return alias_page(self, cursor=cursor, limit=limit)

    def source_page(self, *, cursor=None, limit=50):
        from .storage_queries import source_page

        return source_page(self, cursor=cursor, limit=limit)

    def query_summary(self):
        """Aggregate diagnostic evidence, without an integrity scan."""
        from .storage_queries import summary

        with self.read_snapshot() as db:
            return summary(db)

    @staticmethod
    def inspect_summary(path, *, busy_timeout_ms=2000, verify_integrity=False):
        """Offline doctor reader; does not construct a writer or recover state."""
        from .storage_queries import inspect_summary

        return inspect_summary(
            path, busy_timeout_ms=busy_timeout_ms, verify_integrity=verify_integrity
        )

    @staticmethod
    def inspect_source_page(path, *, cursor=None, limit=50, busy_timeout_ms=2000):
        """Offline capability evidence; does not change source continuity."""
        from .storage_queries import inspect_source_page

        return inspect_source_page(
            path, cursor=cursor, limit=limit, busy_timeout_ms=busy_timeout_ms
        )

    def eligibility_after(self, sequence: int = 0, *, limit: int = 100) -> tuple[Eligibility, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise StorageError("invalid_query_limit")
        with self.read_snapshot() as db:
            return tuple(
                Eligibility(**dict(row))
                for row in db.execute(
                    "SELECT * FROM eligibility WHERE sequence>? ORDER BY sequence LIMIT ?",
                    (sequence, limit),
                )
            )

    def set_record_metadata(
        self,
        record_id: str,
        *,
        seen: bool | None = None,
        snoozed_until: datetime | None = None,
        clear_snooze: bool = False,
        suppressed: bool | None = None,
        now: datetime,
    ) -> None:
        if (
            any(value is not None and type(value) is not bool for value in (seen, suppressed))
            or type(clear_snooze) is not bool
        ):
            raise StorageError("invalid_record_metadata")
        if snoozed_until is not None and (
            clear_snooze or utc_datetime(snoozed_until) <= utc_datetime(now)
        ):
            raise StorageError("invalid_snooze")
        with self.transaction() as db:
            if (
                db.execute("SELECT 1 FROM records WHERE record_id=?", (record_id,)).fetchone()
                is None
            ):
                raise StorageError("record_not_found")
            if seen is not None:
                db.execute("UPDATE records SET seen=? WHERE record_id=?", (int(seen), record_id))
            if suppressed is not None:
                db.execute(
                    "UPDATE records SET suppressed=? WHERE record_id=?",
                    (int(suppressed), record_id),
                )
                if suppressed:
                    db.execute(
                        "UPDATE eligibility SET kind='cancelled' WHERE record_id=? AND kind IN ('candidate','historical_summary')",
                        (record_id,),
                    )
            if snoozed_until is not None or clear_snooze:
                db.execute(
                    "UPDATE records SET snoozed_until=? WHERE record_id=?",
                    (_stamp(snoozed_until) if snoozed_until else None, record_id),
                )

    def _disconnect(self, db, producer_id: str, now: datetime) -> None:
        records = tuple(
            _load_projection(row[0])
            for row in db.execute(
                "SELECT projection FROM records WHERE producer_id=? AND reducer_retained=1",
                (producer_id,),
            )
        )
        old = db.execute(
            "SELECT health FROM sources WHERE producer_id=?", (producer_id,)
        ).fetchone()
        sources = (HEALTH.validate_json(old[0]),) if old and old[0] else ()
        state = disconnect_source(MeshState(records=records, sources=sources), producer_id, now=now)
        for record in state.records:
            self._put_record(db, record, now)
        for health in state.sources:
            db.execute(
                "UPDATE sources SET health=? WHERE producer_id=?",
                (HEALTH.dump_json(health).decode(), producer_id),
            )

    def _restart(self, now: datetime) -> None:
        with self.transaction() as db:
            # v1 had no orphan working-set bound. Refuse excess live state (or
            # prune eligible History) before any source-wide reducer allocation.
            self._prune(db, now)
            for row in db.execute("SELECT producer_id FROM sources").fetchall():
                self._disconnect(db, row[0], now)
            self._age(db, now)
            db.execute(
                "INSERT OR REPLACE INTO metadata VALUES ('runtime_started_at',?)", (_stamp(now),)
            )

    def _age(self, db, now: datetime) -> None:
        for row in db.execute("SELECT projection FROM records WHERE reducer_retained=1").fetchall():
            record = _load_projection(row[0])
            aged = age_state(MeshState(records=(record,)), now=now).records[0]
            if aged != record:
                self._put_record(db, aged, now)
                self._recheck_record_eligibility(db, aged)

    def age_records(self, *, now: datetime) -> None:
        with self.transaction() as db:
            self._age(db, now)
            self._prune(db, now)

    def _prune(self, db, now: datetime) -> None:
        # Snapshot-less live records consume bounded working-set slots too.
        count = db.execute("SELECT count(*) FROM records WHERE reducer_retained=1").fetchone()[0]
        cutoff = _stamp(utc_datetime(now) - timedelta(days=self._settings(db).retention_days))
        candidates = db.execute(
            "SELECT record_key,projection,history_since FROM records WHERE detail_retained=1 AND history_since IS NOT NULL ORDER BY history_since,record_key"
        ).fetchall()
        for row in candidates:
            if count <= self.detail_limit and row["history_since"] > cutoff:
                continue
            record = _load_projection(row["projection"])
            if record.current_confirmed:
                continue
            compact = replace(record, snapshot=None, limitations=tuple(record.limitations))
            db.execute(
                "UPDATE records SET projection=?,detail_retained=0,reducer_retained=0 WHERE record_key=?",
                (_dump_projection(compact), row["record_key"]),
            )
            db.execute("DELETE FROM event_details WHERE record_key=?", (row["record_key"],))
            count -= 1
        if count > self.detail_limit:
            raise CapacityError("detail_capacity_reached")
        # Expire bodies independently: a compact projection cannot regain detail
        # through rejected traffic, and standalone health/audit/orphan bodies have
        # a finite lifetime even if no projection ever reaches History. This join
        # scans only the separately capped body table, never lifetime identities.
        db.execute(
            "DELETE FROM event_details WHERE sequence IN ("
            "SELECT d.sequence FROM event_details AS d "
            "JOIN events AS e ON e.sequence=d.sequence "
            "LEFT JOIN records AS r ON r.record_key=d.record_key "
            "WHERE r.reducer_retained=0 OR r.history_since<=? OR "
            "((r.record_key IS NULL OR r.detail_retained=0) AND e.received_at<=?))",
            (cutoff, cutoff),
        )
        db.execute(
            "DELETE FROM event_details WHERE sequence NOT IN (SELECT sequence FROM event_details ORDER BY sequence DESC LIMIT ?)",
            (self.detail_limit,),
        )

    def project_alias(self, identity: str | None, *, local_path: str | None = None) -> ProjectAlias:
        if identity is None and local_path is None:
            return ProjectAlias("unknown", "Unknown project", None)
        if identity is not None and (
            not isinstance(identity, str) or not identity or len(identity) > 2048
        ):
            raise StorageError("invalid_project_identity")
        if local_path is not None and (
            not isinstance(local_path, str) or len(local_path) > 2048 or "\x00" in local_path
        ):
            raise StorageError("invalid_project_path")
        normalized = (
            "identity:" + identity
            if identity is not None
            else "path:" + ntpath.normcase(ntpath.normpath(local_path))
        )
        with self.transaction() as db:
            row = db.execute(
                "SELECT identity,alias,local_path FROM aliases WHERE identity=?", (normalized,)
            ).fetchone()
            if row:
                return ProjectAlias(*row)
            ordinal = db.execute("SELECT coalesce(max(ordinal),0)+1 FROM aliases").fetchone()[0]
            alias = f"Project {ordinal}"
            db.execute(
                "INSERT INTO aliases VALUES (?,?,?,?)", (normalized, ordinal, alias, local_path)
            )
            return ProjectAlias(normalized, alias, local_path)

    def rename_alias_checked(
        self, identity: str, alias: str, *, expected_revision: int
    ) -> Settings:
        """Atomically rename an existing alias against the UI's profile revision."""
        if type(expected_revision) is not int:
            raise SettingsConflict("stale_settings_revision")
        return self._rename_alias(identity, alias, expected_revision=expected_revision)

    def rename_alias(self, identity: str, alias: str) -> None:
        """Controlled legacy rename; still advances the shared profile revision."""
        self._rename_alias(identity, alias)

    def _rename_alias(
        self, identity: str, alias: str, *, expected_revision: int | None = None
    ) -> Settings:
        validate_alias(alias)
        with self.transaction() as db:
            current = self._settings(db)
            if expected_revision is not None and current.revision != expected_revision:
                raise SettingsConflict("stale_settings_revision")
            if (
                db.execute(
                    "UPDATE aliases SET alias=? WHERE identity=?", (alias, identity)
                ).rowcount
                != 1
            ):
                raise SettingsError("project_alias_not_found")
            # Same-value renames advance revision just like update_settings({}).
            # An alias is not a new destination or a capture-policy grant.
            updated = revised_settings(current, {})
            db.execute("UPDATE settings SET body=? WHERE singleton=1", (updated.model_dump_json(),))
            return updated

    def backup(self, destination: Path | str) -> Path:
        destination = Path(destination).absolute()
        if destination == self.path or destination.exists():
            raise StorageError("backup_destination_exists")
        with self._mutex:
            if self._db is None or self._db.in_transaction:
                raise StorageError("backup_requires_idle_writer")
            atomic_write_owner_only(destination, b"")
            backup = sqlite3.connect(destination, isolation_level=None)
            try:
                self._db.backup(backup)
                if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise StorageError("backup_integrity_failed")
            except sqlite3.Error:
                raise StorageError("backup_failed") from None
            finally:
                backup.close()
        return destination

    def install_extension(self, name: str, version: int, statements: tuple[str, ...]) -> None:
        """Controlled DB-only migration seam; extension owns its prefixed tables.

        Call before delivery starts. Statements are trusted application constants,
        never event/user SQL. Versions advance one step; existing versions no-op.
        """
        if (
            not name
            or any(c not in "abcdefghijklmnopqrstuvwxyz_" for c in name)
            or type(version) is not int
            or version < 1
        ):
            raise StorageError("invalid_extension")
        with self._mutex:
            row = self._db.execute(
                "SELECT version FROM extensions WHERE name=?", (name,)
            ).fetchone()
            if (row[0] if row else 0) < version:
                self.backup(
                    self.path.with_name(
                        self.path.name + f".pre-{name}-{version}-{uuid.uuid4().hex}.bak"
                    )
                )
        with self.transaction() as db:
            row = db.execute("SELECT version FROM extensions WHERE name=?", (name,)).fetchone()
            current = row[0] if row else 0
            if current > version:
                raise StorageError("newer_extension_schema")
            if current == version:
                return
            if version != current + 1:
                raise StorageError("extension_version_gap")
            for statement in statements:
                db.execute(statement)
            self._fault("extension_applied")
            db.execute("INSERT OR REPLACE INTO extensions VALUES (?,?)", (name, version))
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise StorageError("migration_integrity_failed")

    @classmethod
    def restore_backup(
        cls,
        backup_path: Path | str,
        destination: Path | str,
        *,
        now: datetime,
        fault_hook: Callable[[str], None] | None = None,
    ) -> SQLiteStore:
        """Restore into a NEW owner-only location, leaving the live DB untouched.

        Runtime must be stopped for a later operator-selected directory swap. No
        extension may deliver before observing the changed recovery_epoch; old
        intents/attempts must be suppressed regardless of their backup status.
        """
        backup_path, destination = Path(backup_path).absolute(), Path(destination).absolute()
        if destination.exists():
            raise StorageError("restore_destination_exists")
        staging = destination.with_name(".restore-" + uuid.uuid4().hex + ".db")
        source = target = None
        try:
            assert_owner_only(backup_path)
            source = sqlite3.connect(
                backup_path.as_uri() + "?mode=ro", uri=True, isolation_level=None
            )
            source.execute("PRAGMA trusted_schema=OFF")
            if (
                not 1 <= source.execute("PRAGMA user_version").fetchone()[0] <= SCHEMA_VERSION
                or source.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            ):
                raise StorageError("restore_backup_invalid")
            atomic_write_owner_only(staging, b"")
            target = sqlite3.connect(staging, isolation_level=None)
            source.backup(target)
        except (sqlite3.Error, ValueError):
            raise StorageError("restore_backup_invalid") from None
        finally:
            if target is not None:
                target.close()
            if source is not None:
                source.close()
        store = cls(staging, now=now, fault_hook=fault_hook)
        try:
            with store.transaction() as db:
                db.execute(
                    "INSERT OR REPLACE INTO metadata VALUES ('recovery_epoch',?)",
                    (uuid.uuid4().hex,),
                )
                db.execute(
                    "INSERT OR REPLACE INTO metadata VALUES ('restore_time',?)", (_stamp(now),)
                )
                db.execute("UPDATE eligibility SET kind='restore_suppressed'")
                old = store._settings(db)
                updated = Settings.model_validate(
                    old.model_dump(mode="python")
                    | {
                        "revision": old.revision + 1,
                        "destination_generation": old.destination_generation + 1,
                        "channel_active": False,
                    }
                )
                db.execute(
                    "UPDATE settings SET body=? WHERE singleton=1", (updated.model_dump_json(),)
                )
                store._new_policy(db, updated, now)
                for row in db.execute("SELECT projection FROM records").fetchall():
                    record = _load_projection(row[0])
                    if not record.terminal and record.source_state != SourceState.PENDING:
                        record = replace(
                            record,
                            visibility=VisibilityState.HISTORY,
                            aged=True,
                            current_confirmed=False,
                        )
                    else:
                        record = replace(record, current_confirmed=False)
                    store._put_record(db, record, now)
                db.execute("UPDATE records SET restored=1")
                db.execute(
                    "UPDATE sources SET enabled=0 WHERE json_extract(capabilities,'$.producer_kind')='native'"
                )
                store._fault("restore_applied")
            # A crash before this publication leaves no usable destination.
            # Closing the sole connection checkpoints/removes its WAL first.
            store.close()
            if destination.exists():
                raise StorageError("restore_destination_exists")
            os.replace(staging, destination)
            return cls(destination, now=now)
        except BaseException:
            store.close()
            raise
