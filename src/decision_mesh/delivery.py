"""One synchronous durable worker; no database transaction encloses provider I/O."""

from __future__ import annotations

import hashlib
import json
import math
import random
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from .channels.telegram import TelegramOutcome, TelegramResult
from .contracts import EvidenceClass, SourceState, utc_datetime
from .presentation.models import Layout
from .presentation.renderers import render_telegram_parts
from .settings import DeliveryMode, SettingsConflict
from .storage import SQLiteStore, StoredRecord
from .view import to_presentation_record

RETRY_SECONDS = (5, 15, 60, 300, 900)
MAX_AUTOMATIC_ATTEMPTS = 6
MAX_JITTER_SECONDS = 1.0
MANUAL_DUPLICATE_WARNING = "Retry may send a duplicate. Provider acceptance does not prove reading."
PUBLIC_FIELDS = ("action", "reason", "scope", "chat_title", "source_path", "source_reference")
SCHEMA = (
    "CREATE TABLE dm_delivery_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    (
        "CREATE TABLE dm_delivery_routes (epoch TEXT NOT NULL, generation INTEGER NOT NULL, "
        "blocked_until TEXT, suspended INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(epoch,generation))"
    ),
    (
        "CREATE TABLE dm_delivery_occurrences (occurrence_id TEXT PRIMARY KEY, epoch TEXT NOT NULL, "
        "generation INTEGER NOT NULL, record_id TEXT NOT NULL, revision INTEGER NOT NULL, "
        "content_key TEXT NOT NULL, kind TEXT NOT NULL, sequence INTEGER NOT NULL, policy_ref TEXT, "
        "minimal INTEGER NOT NULL DEFAULT 0, grant_fields TEXT NOT NULL, state TEXT NOT NULL, part_id TEXT, "
        "created_at TEXT NOT NULL, captured_at TEXT NOT NULL, reason TEXT, "
        "UNIQUE(generation,record_id,revision,kind,epoch))"
    ),
    "CREATE INDEX dm_delivery_queue ON dm_delivery_occurrences(state,sequence)",
    "CREATE INDEX dm_delivery_record ON dm_delivery_occurrences(record_id,generation,content_key)",
    (
        "CREATE TABLE dm_delivery_batches (batch_id TEXT PRIMARY KEY, epoch TEXT NOT NULL, "
        "generation INTEGER NOT NULL, mode TEXT NOT NULL, historical INTEGER NOT NULL, "
        "created_at TEXT NOT NULL, max_sequence INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE dm_delivery_parts (part_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL "
        "REFERENCES dm_delivery_batches(batch_id), ordinal INTEGER NOT NULL, state TEXT NOT NULL, "
        "automatic_attempts INTEGER NOT NULL DEFAULT 0, manual_pending INTEGER NOT NULL DEFAULT 0, manual_target TEXT, "
        "next_attempt_at TEXT, UNIQUE(batch_id,ordinal))"
    ),
    (
        "CREATE TABLE dm_delivery_members (part_id TEXT NOT NULL REFERENCES dm_delivery_parts(part_id), "
        "occurrence_id TEXT NOT NULL REFERENCES dm_delivery_occurrences(occurrence_id), "
        "PRIMARY KEY(part_id,occurrence_id))"
    ),
    (
        "CREATE TABLE dm_delivery_attempts (attempt_id TEXT PRIMARY KEY, part_id TEXT NOT NULL "
        "REFERENCES dm_delivery_parts(part_id), ordinal INTEGER NOT NULL, epoch TEXT NOT NULL, "
        "started_at TEXT NOT NULL, finished_at TEXT, outcome TEXT NOT NULL, "
        "manual INTEGER NOT NULL, provider_message_id INTEGER, next_attempt_at TEXT, "
        "UNIQUE(part_id,ordinal))"
    ),
    (
        "CREATE TABLE dm_delivery_attempt_members (attempt_id TEXT NOT NULL "
        "REFERENCES dm_delivery_attempts(attempt_id), occurrence_id TEXT NOT NULL, "
        "PRIMARY KEY(attempt_id,occurrence_id))"
    ),
    (
        "CREATE TABLE dm_delivery_snoozes (record_id TEXT PRIMARY KEY, deadline TEXT NOT NULL, "
        "handled INTEGER NOT NULL DEFAULT 0)"
    ),
)


class DeliveryError(ValueError):
    """Fixed diagnostic code, never source/provider content."""


class Channel(Protocol):
    def send_message(self, chat_id: int, text: str) -> TelegramResult: ...


class Clock(Protocol):
    def utcnow(self) -> datetime: ...
    def monotonic(self) -> float: ...


class SystemClock:
    def utcnow(self):
        return datetime.now(UTC)

    def monotonic(self):
        return time.monotonic()


@dataclass(frozen=True)
class TickResult:
    attempted: int
    accepted: int
    next_wake_seconds: float


@dataclass(frozen=True)
class Occurrence:
    occurrence_id: str
    record_id: str
    revision: int
    kind: str
    state: str
    generation: int
    part_id: str | None
    captured_at: datetime
    reason: str | None


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    part_id: str
    ordinal: int
    started_at: datetime
    finished_at: datetime | None
    outcome: str
    manual: bool
    provider_message_id: int | None
    next_attempt_at: datetime | None


def _stamp(value):
    return utc_datetime(value).isoformat()


def _content(stored):
    p = stored.projection
    # Internal comparison only, never a public field or authority merge.
    return hashlib.sha256(f"{p.snapshot_digest}:{p.captured_at}".encode()).hexdigest()


def _eligible(stored: StoredRecord | None, *, explicit=False):
    if (
        stored is None
        or stored.projection.snapshot is None
        or stored.projection.captured_at is None
    ):
        return False
    p = stored.projection
    return bool(
        not p.terminal
        and not stored.suppressed
        and (explicit or not stored.restored)
        and p.evidence_class != EvidenceClass.GATE_OBSERVED
        and (p.source_state != SourceState.PENDING or p.current_confirmed)
    )


class DeliveryWorker:
    """Runtime owns one instance. tick may block on its bounded channel call.

    Controls serialize with tick. Fake Clock/Channel and named crash points are
    the test seam; no host runtime, provider setup or background thread is owned.
    """

    def __init__(
        self,
        store: SQLiteStore,
        channel: Channel,
        *,
        clock: Clock | None = None,
        jitter: Callable[[int], float] | None = None,
        fault_hook: Callable[[str], None] | None = None,
        project_alias: Callable[[StoredRecord], str] | None = None,
    ):
        self.store, self.channel = store, channel
        self.clock = clock or SystemClock()
        self.jitter = jitter or (lambda _: random.uniform(0, MAX_JITTER_SECONDS))
        self.fault_hook = fault_hook
        self.project_alias = project_alias or (lambda _: "Project 1")
        self._lock = threading.RLock()
        self._ticking = False
        self._anchor_utc, self._anchor_mono = (
            utc_datetime(self.clock.utcnow()),
            self.clock.monotonic(),
        )
        store.install_extension("delivery", 1, SCHEMA)
        self._recover()

    def _now(self):
        logical = self._anchor_utc + timedelta(
            seconds=max(0, self.clock.monotonic() - self._anchor_mono)
        )
        wall = utc_datetime(self.clock.utcnow())
        if wall > logical:
            self._anchor_utc, self._anchor_mono = wall, self.clock.monotonic()
            return wall
        return logical

    def _fault(self, point):
        if self.fault_hook:
            self.fault_hook(point)

    def _rows(self, sql, parameters=()):
        with self.store.read_snapshot() as db:
            return [dict(row) for row in db.execute(sql, parameters)]

    @staticmethod
    def _state(db, key, default=None):
        row = db.execute("SELECT value FROM dm_delivery_state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    @staticmethod
    def _put_state(db, key, value):
        db.execute(
            "INSERT INTO dm_delivery_state VALUES (?,?) ON CONFLICT(key) "
            "DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def _delay(self, number, retry_after=None):
        base = RETRY_SECONDS[min(max(number - 1, 0), len(RETRY_SECONDS) - 1)]
        jitter = float(self.jitter(number))
        if not math.isfinite(jitter) or not 0 <= jitter <= MAX_JITTER_SECONDS:
            raise DeliveryError("jitter_out_of_bounds")
        return max(base + jitter, retry_after or 0)

    def _recover(self):
        now, epoch = self._now(), self.store.recovery_state().epoch
        with self.store.transaction() as db:
            db.execute(
                "UPDATE dm_delivery_occurrences SET state='suppressed',reason='restored_epoch' "
                "WHERE epoch<>?",
                (epoch,),
            )
            rows = db.execute(
                "SELECT a.*,p.automatic_attempts FROM dm_delivery_attempts a "
                "JOIN dm_delivery_parts p USING(part_id) WHERE a.outcome='started'"
            ).fetchall()
            for row in rows:
                deadline = (
                    utc_datetime(row["next_attempt_at"])
                    if row["next_attempt_at"]
                    else utc_datetime(row["started_at"])
                    + timedelta(seconds=self._delay(row["automatic_attempts"]))
                )
                db.execute(
                    "UPDATE dm_delivery_attempts SET outcome='outcome_unknown',finished_at=?, "
                    "next_attempt_at=? WHERE attempt_id=?",
                    (_stamp(now), _stamp(deadline), row["attempt_id"]),
                )
                state = (
                    "retry"
                    if row["epoch"] == epoch
                    and not row["manual"]
                    and row["automatic_attempts"] < MAX_AUTOMATIC_ATTEMPTS
                    else "outcome_unknown"
                )
                db.execute(
                    "UPDATE dm_delivery_parts SET state=?,next_attempt_at=? WHERE part_id=?",
                    (state, _stamp(deadline), row["part_id"]),
                )
                db.execute(
                    "UPDATE dm_delivery_occurrences SET state='outcome_unknown' "
                    "WHERE part_id=? AND epoch=? AND state='inflight'",
                    (row["part_id"], epoch),
                )
            self._fault("recovery_before_commit")

    def occurrences(self, record_id: str | None = None) -> tuple[Occurrence, ...]:
        rows = self._rows(
            "SELECT * FROM dm_delivery_occurrences"
            + (" WHERE record_id=?" if record_id else "")
            + " ORDER BY sequence,created_at",
            (record_id,) if record_id else (),
        )
        return tuple(
            Occurrence(
                r["occurrence_id"],
                r["record_id"],
                r["revision"],
                r["kind"],
                r["state"],
                r["generation"],
                r["part_id"],
                utc_datetime(r["captured_at"]),
                r["reason"],
            )
            for r in rows
        )

    def attempts(self, occurrence_id: str | None = None) -> tuple[Attempt, ...]:
        rows = self._rows(
            "SELECT a.* FROM dm_delivery_attempts a"
            + (
                " JOIN dm_delivery_attempt_members m USING(attempt_id) WHERE m.occurrence_id=?"
                if occurrence_id
                else ""
            )
            + " ORDER BY a.started_at,a.ordinal",
            (occurrence_id,) if occurrence_id else (),
        )
        return tuple(
            Attempt(
                r["attempt_id"],
                r["part_id"],
                r["ordinal"],
                utc_datetime(r["started_at"]),
                utc_datetime(r["finished_at"]) if r["finished_at"] else None,
                r["outcome"],
                bool(r["manual"]),
                r["provider_message_id"],
                utc_datetime(r["next_attempt_at"]) if r["next_attempt_at"] else None,
            )
            for r in rows
        )

    def occurrence_page(self, *, record_id=None, cursor=None, limit=50):
        """Read compact delivery evidence without changing worker or source state."""
        from .delivery_queries import occurrence_page

        return occurrence_page(self, record_id=record_id, cursor=cursor, limit=limit)

    @staticmethod
    def inspect_summary(path, *, busy_timeout_ms=2000):
        """Offline doctor reader; no worker construction or crash recovery."""
        from .delivery_queries import inspect_summary

        return inspect_summary(path, busy_timeout_ms=busy_timeout_ms)

    def _insert(
        self,
        db,
        stored,
        settings,
        epoch,
        now,
        *,
        sequence=0,
        policy_ref=None,
        minimal=False,
        kind=None,
    ):
        p, content = stored.projection, _content(stored)
        if kind is None:
            previous = db.execute(
                "SELECT 1 FROM dm_delivery_occurrences WHERE epoch=? AND generation=? AND record_id=? LIMIT 1",
                (epoch, settings.destination_generation, p.record_id),
            ).fetchone()
            kind = "historical_summary" if p.aged else "material_update" if previous else "initial"
        duplicate = db.execute(
            "SELECT occurrence_id FROM dm_delivery_occurrences WHERE epoch=? AND generation=? "
            "AND record_id=? AND content_key=? AND ((?='snooze_reminder' AND kind='snooze_reminder') OR "
            "(?<>'snooze_reminder' AND kind<>'snooze_reminder')) LIMIT 1",
            (epoch, settings.destination_generation, p.record_id, content, kind, kind),
        ).fetchone()
        if duplicate:
            return duplicate[0]
        occurrence_id = str(uuid4())
        policy = self.store.get_policy(policy_ref)
        grant = [] if minimal or policy is None else sorted(policy.effective_fields(settings))
        db.execute(
            "INSERT INTO dm_delivery_occurrences VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                occurrence_id,
                epoch,
                settings.destination_generation,
                p.record_id,
                p.request_revision,
                content,
                kind,
                sequence,
                policy_ref,
                int(minimal),
                json.dumps(grant),
                "queued",
                None,
                _stamp(now),
                _stamp(p.captured_at),
                None,
            ),
        )
        return occurrence_id

    def include_current(self, record_ids: Iterable[str]) -> tuple[str, ...]:
        """Explicit local inclusion is minimal; repeated inclusion coalesces."""
        with self._lock:
            now, settings = self._now(), self.store.get_settings()
            if not settings.channel_active or settings.destination is None:
                raise DeliveryError("inactive_route")
            epoch = self.store.recovery_state().epoch
            records = [self.store.get_record(r) for r in dict.fromkeys(record_ids)]
            if any(not _eligible(r, explicit=True) for r in records):
                raise DeliveryError("record_not_eligible")
            policy = self.store.current_policy()
            with self.store.transaction() as db:
                return tuple(
                    self._insert(
                        db,
                        r,
                        settings,
                        epoch,
                        now,
                        policy_ref=policy.policy_ref,
                        minimal=True,
                        kind="explicit",
                    )
                    for r in records
                )

    def manual_retry(self, occurrence_id: str, *, acknowledge_duplicate: bool = False) -> str:
        """One explicit attempt, never a reset of the six-attempt automatic budget."""
        if type(acknowledge_duplicate) is not bool:
            raise DeliveryError("invalid_duplicate_acknowledgement")
        with self._lock:
            rows = self._rows(
                "SELECT * FROM dm_delivery_occurrences WHERE occurrence_id=?", (occurrence_id,)
            )
            if not rows:
                raise DeliveryError("occurrence_not_found")
            row = rows[0]
            if row["state"] in {"cancelled", "suppressed"}:
                raise DeliveryError("occurrence_not_eligible")
            # Queued alone does not imply a scheduled attempt: a post-start
            # abort can leave its part failed. Inspect that part below so a new
            # explicit action can authorize one manual retry without resetting it.
            if row["part_id"] is None or row["state"] == "inflight":
                return occurrence_id
            attempts = self.attempts(occurrence_id)
            if (
                any(a.outcome in {"accepted", "outcome_unknown"} for a in attempts)
                and not acknowledge_duplicate
            ):
                raise DeliveryError("duplicate_acknowledgement_required")
            with self.store.transaction() as db:
                part = db.execute(
                    "SELECT * FROM dm_delivery_parts WHERE part_id=?", (row["part_id"],)
                ).fetchone()
                if part["manual_pending"] and part["manual_target"] != occurrence_id:
                    raise DeliveryError("part_retry_already_pending")
                if part["manual_pending"] or part["state"] in {"ready", "retry", "inflight"}:
                    return occurrence_id
                db.execute(
                    "UPDATE dm_delivery_parts SET state='ready',manual_pending=1,manual_target=?,next_attempt_at=? "
                    "WHERE part_id=?",
                    (occurrence_id, _stamp(self._now()), row["part_id"]),
                )
                db.execute(
                    "UPDATE dm_delivery_occurrences SET state='queued' WHERE occurrence_id=? "
                    "AND state NOT IN ('cancelled','suppressed')",
                    (occurrence_id,),
                )
            return occurrence_id

    def resume_route(self):
        """Explicit local retry of a provider-suspended route; retains generation."""
        with self._lock:
            now, epoch = self._now(), self.store.recovery_state().epoch
            for _ in range(3):
                settings = self.store.get_settings()
                try:
                    settings = self.store.update_settings(
                        settings.revision, {"provider_suspended": False}, now=now
                    )
                    break
                except SettingsConflict:
                    continue
            else:
                raise DeliveryError("settings_changed")
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE dm_delivery_routes SET suspended=0 WHERE epoch=? AND generation=?",
                    (epoch, settings.destination_generation),
                )

    def _sync(self, now):
        self.store.age_records(now=now)
        settings, epoch = self.store.get_settings(), self.store.recovery_state().epoch
        with self.store.read_snapshot() as db:
            cursor = int(self._state(db, "eligibility_cursor", "0"))
        facts = self.store.eligibility_after(cursor, limit=1000)
        candidates = []
        for fact in facts:
            if fact.kind not in {"candidate", "historical_summary"} or fact.recovery_epoch != epoch:
                continue
            stored, policy = (
                self.store.get_record(fact.record_id),
                self.store.get_policy(fact.policy_ref),
            )
            if (
                _eligible(stored)
                and policy is not None
                and policy.permits_route(settings)
                and stored.projection.capture_policy_ref == fact.policy_ref
            ):
                candidates.append((fact, stored))
        with self.store.transaction() as db:
            for fact, stored in candidates:
                self._insert(
                    db,
                    stored,
                    settings,
                    epoch,
                    now,
                    sequence=fact.sequence,
                    policy_ref=fact.policy_ref,
                )
            if facts:
                self._put_state(db, "eligibility_cursor", facts[-1].sequence)
            mode, interval = self._state(db, "mode"), self._state(db, "interval")
            changed = mode != settings.delivery_mode.value
            if changed or interval != str(settings.digest_interval_minutes):
                self._put_state(
                    db,
                    "digest_due",
                    _stamp(now + timedelta(minutes=settings.digest_interval_minutes)),
                )
            if changed:
                untouched = [
                    r[0]
                    for r in db.execute(
                        "SELECT part_id FROM dm_delivery_parts "
                        "WHERE automatic_attempts=0 AND NOT EXISTS (SELECT 1 FROM dm_delivery_attempts a "
                        "WHERE a.part_id=dm_delivery_parts.part_id) AND state='ready'"
                    )
                ]
                for part_id in untouched:
                    self._dissolve(db, part_id)
            self._put_state(db, "mode", settings.delivery_mode.value)
            self._put_state(db, "interval", settings.digest_interval_minutes)
        self._reconcile(now, settings, epoch)
        self._snoozes(now, settings, epoch)

    @staticmethod
    def _dissolve(db, part_id):
        db.execute(
            "UPDATE dm_delivery_occurrences SET part_id=NULL WHERE part_id=? AND state='queued'",
            (part_id,),
        )
        db.execute("UPDATE dm_delivery_parts SET state='cancelled' WHERE part_id=?", (part_id,))

    def _reconcile(self, now, settings, epoch):
        rows = self._rows(
            "SELECT o.*, (SELECT count(*) FROM dm_delivery_attempts a "
            "WHERE a.part_id=o.part_id) attempt_count FROM dm_delivery_occurrences o "
            "WHERE o.state NOT IN ('accepted','cancelled','suppressed')"
        )
        changes = []
        for row in rows:
            stored, reason = self.store.get_record(row["record_id"]), None
            if row["epoch"] != epoch:
                reason = "restored_epoch"
            elif (
                row["generation"] != settings.destination_generation or not settings.channel_active
            ):
                reason = "route_changed"
            elif not _eligible(stored, explicit=bool(row["minimal"])):
                # Lost native continuity temporarily suspends eligibility.
                if (
                    stored is not None
                    and stored.projection.last_known_pending
                    and not stored.suppressed
                    and not stored.projection.terminal
                ):
                    continue
                reason = "source_ineligible"
            elif _content(stored) != row["content_key"]:
                reason = "source_updated"
            elif (
                stored.projection.aged
                and stored.snoozed_until
                and stored.projection.aging_deadline
                and stored.snoozed_until >= stored.projection.aging_deadline
                and row["attempt_count"] == 0
            ):
                reason = "snooze_hide"
            if reason:
                changes.append((row, reason, False))
            elif (
                stored
                and stored.projection.aged
                and row["kind"] not in {"historical_summary", "snooze_reminder"}
                and row["attempt_count"] == 0
            ):
                changes.append((row, None, True))
            elif stored and stored.projection.aged and row["kind"] == "snooze_reminder":
                changes.append((row, "reminder_aged", False))
        with self.store.transaction() as db:
            for row, reason, age in changes:
                if age:
                    if row["part_id"]:
                        self._dissolve(db, row["part_id"])
                    db.execute(
                        "UPDATE dm_delivery_occurrences SET kind='historical_summary' WHERE occurrence_id=?",
                        (row["occurrence_id"],),
                    )
                else:
                    db.execute(
                        "UPDATE dm_delivery_occurrences SET state=?,reason=? WHERE occurrence_id=?",
                        (
                            "suppressed" if reason == "restored_epoch" else "cancelled",
                            reason,
                            row["occurrence_id"],
                        ),
                    )

    def _snoozes(self, now, settings, epoch):
        after = ""
        while True:
            records = self.store.list_records(limit=1000, after_record_id=after)
            if not records:
                break
            for stored in records:
                deadline = stored.snoozed_until
                if deadline is None:
                    continue
                prior = self._rows(
                    "SELECT * FROM dm_delivery_snoozes WHERE record_id=?",
                    (stored.projection.record_id,),
                )
                if prior and prior[0]["deadline"] == _stamp(deadline) and prior[0]["handled"]:
                    continue
                expired = deadline <= now
                policy = self.store.get_policy(stored.projection.capture_policy_ref)
                pending = self._rows(
                    "SELECT state,kind FROM dm_delivery_occurrences WHERE record_id=? "
                    "AND generation=? AND epoch=? AND content_key=?",
                    (
                        stored.projection.record_id,
                        settings.destination_generation,
                        epoch,
                        _content(stored),
                    ),
                )
                reminder = (
                    expired
                    and _eligible(stored)
                    and not stored.projection.aged
                    and (
                        stored.projection.aging_deadline is None
                        or deadline < stored.projection.aging_deadline
                    )
                    and policy is not None
                    and policy.permits_route(settings)
                    and any(
                        r["state"] == "accepted" and r["kind"] != "historical_summary"
                        for r in pending
                    )
                    and not any(
                        r["state"] in {"queued", "inflight", "outcome_unknown", "failed"}
                        for r in pending
                    )
                )
                with self.store.transaction() as db:
                    db.execute(
                        "INSERT INTO dm_delivery_snoozes VALUES (?,?,?) ON CONFLICT(record_id) "
                        "DO UPDATE SET deadline=excluded.deadline,handled=excluded.handled",
                        (stored.projection.record_id, _stamp(deadline), int(expired)),
                    )
                    if reminder:
                        self._insert(
                            db,
                            stored,
                            settings,
                            epoch,
                            now,
                            policy_ref=policy.policy_ref,
                            kind="snooze_reminder",
                        )
            after = records[-1].projection.record_id

    def _view(self, row, stored, settings, now):
        policy = self.store.get_policy(row["policy_ref"])
        grant = (
            frozenset()
            if row["minimal"] or policy is None
            else frozenset(json.loads(row["grant_fields"])) & policy.effective_fields(settings)
        )
        return to_presentation_record(
            stored,
            now=now,
            project_alias=self.project_alias(stored),
            device_alias=settings.device_alias,
            allowed_fields=grant,
        )

    def _plan(self, now):
        settings, epoch = self.store.get_settings(), self.store.recovery_state().epoch
        if not settings.channel_active or settings.global_pause or settings.provider_suspended:
            return
        with self.store.read_snapshot() as db:
            due = utc_datetime(self._state(db, "digest_due", _stamp(now)))
        if settings.delivery_mode == DeliveryMode.DIGEST and now < due:
            return
        queued = self._rows(
            "SELECT * FROM dm_delivery_occurrences WHERE state='queued' "
            "AND part_id IS NULL AND epoch=? AND generation=? ORDER BY sequence,created_at",
            (epoch, settings.destination_generation),
        )
        prepared = []
        for row in queued:
            stored = self.store.get_record(row["record_id"])
            if not _eligible(stored, explicit=bool(row["minimal"])) or (
                stored.snoozed_until and stored.snoozed_until > now
            ):
                continue
            prepared.append((row, self._view(row, stored, settings, now)))
        groups = []
        for historical in (False, True):
            selection = [
                (r, v) for r, v in prepared if (r["kind"] == "historical_summary") == historical
            ]
            if settings.delivery_mode == DeliveryMode.IMMEDIATE and not historical:
                groups.extend([(False, [(r, v)]) for r, v in selection])
            elif selection:
                groups.append((historical, selection))
        with self.store.transaction() as db:
            for historical, group in groups:
                batch_id = str(uuid4())
                db.execute(
                    "INSERT INTO dm_delivery_batches VALUES (?,?,?,?,?,?,?)",
                    (
                        batch_id,
                        epoch,
                        settings.destination_generation,
                        settings.delivery_mode.value,
                        int(historical),
                        _stamp(now),
                        max(r["sequence"] for r, _ in group),
                    ),
                )
                # Reserve room for changed aliases, ages, layouts and historical
                # wording. Attempted membership stays fixed on every retry.
                chunks, chunk, size = [], [], 0
                for row, view in group:
                    rendered = render_telegram_parts(
                        (view,), Layout.FRIENDLY, allowed_fields=PUBLIC_FIELDS
                    )[0].text
                    cost = max(900, len(rendered.encode("utf-16-le")) // 2 + 350)
                    if chunk and size + cost > 3250:
                        chunks.append(chunk)
                        chunk, size = [], 0
                    chunk.append(row)
                    size += cost
                if chunk:
                    chunks.append(chunk)
                for number, members in enumerate(chunks):
                    part_id = str(uuid4())
                    db.execute(
                        "INSERT INTO dm_delivery_parts VALUES (?,?,?,'ready',0,0,NULL,?)",
                        (part_id, batch_id, number, _stamp(now)),
                    )
                    for row in members:
                        db.execute(
                            "INSERT INTO dm_delivery_members VALUES (?,?)",
                            (part_id, row["occurrence_id"]),
                        )
                        db.execute(
                            "UPDATE dm_delivery_occurrences SET part_id=? WHERE occurrence_id=?",
                            (part_id, row["occurrence_id"]),
                        )
            if settings.delivery_mode == DeliveryMode.DIGEST:
                self._put_state(
                    db,
                    "digest_due",
                    _stamp(now + timedelta(minutes=settings.digest_interval_minutes)),
                )
            self._fault("plan_before_commit")

    def _prepare(self, part_id, now):
        # Repeated immediately before attempt-start. A concurrent change while a
        # call is already in flight cannot recall a timestamped provider message.
        epoch, settings = self.store.recovery_state().epoch, self.store.get_settings()
        part = self._rows(
            "SELECT p.*,b.epoch,b.generation,b.historical,b.mode FROM dm_delivery_parts p "
            "JOIN dm_delivery_batches b USING(batch_id) WHERE part_id=?",
            (part_id,),
        )[0]
        if part["state"] not in {"ready", "retry", "inflight"}:
            return None
        if part["epoch"] != epoch or part["generation"] != settings.destination_generation:
            return None
        if (
            not settings.channel_active
            or settings.destination is None
            or settings.global_pause
            or settings.provider_suspended
        ):
            return None
        route = self._rows(
            "SELECT * FROM dm_delivery_routes WHERE epoch=? AND generation=?",
            (epoch, settings.destination_generation),
        )
        if route and (
            route[0]["suspended"]
            or route[0]["blocked_until"]
            and utc_datetime(route[0]["blocked_until"]) > now
        ):
            return None
        rows = self._rows(
            "SELECT o.* FROM dm_delivery_members m JOIN dm_delivery_occurrences o "
            "USING(occurrence_id) WHERE m.part_id=? AND o.part_id=m.part_id AND o.state NOT IN ('cancelled','suppressed','accepted') "
            "ORDER BY o.sequence,o.created_at",
            (part_id,),
        )
        selected, views = [], []
        for row in rows:
            if part["manual_target"] and row["occurrence_id"] != part["manual_target"]:
                continue
            stored, policy = (
                self.store.get_record(row["record_id"]),
                self.store.get_policy(row["policy_ref"]),
            )
            if (
                not _eligible(stored, explicit=bool(row["minimal"]))
                or policy is None
                or not policy.permits_route(settings)
                or _content(stored) != row["content_key"]
            ):
                return None
            registration = self.store.source_registration(stored.projection.key[0])
            if (
                registration is None
                or not registration["enabled"]
                or (stored.projection.producer_kind == "native" and not registration["qualified"])
            ):
                return None
            if stored.snoozed_until and stored.snoozed_until > now:
                return None
            if row["kind"] == "snooze_reminder" and stored.projection.aged:
                return None
            selected.append(row)
            views.append(self._view(row, stored, settings, now))
        if not selected:
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE dm_delivery_parts SET state='cancelled' WHERE part_id=?", (part_id,)
                )
            return None
        rendered = render_telegram_parts(
            views, settings.telegram_layout.value, allowed_fields=PUBLIC_FIELDS
        )
        if len(rendered) != 1:
            rendered = render_telegram_parts(views, Layout.COMPACT)
        if len(rendered) != 1:
            raise DeliveryError("stable_part_capacity")
        text = rendered[0].text
        if part["historical"]:
            text = text.replace("Decision Mesh\n\n", "Decision Mesh — HISTORICAL\n\n", 1)
        elif part["mode"] == DeliveryMode.DIGEST:
            text = text.replace(
                "Decision Mesh\n\n", "Decision Mesh — observed since the last digest\n\n", 1
            )
        if len(text.encode("utf-16-le")) // 2 > 3500:
            text = render_telegram_parts(views, Layout.COMPACT)[0].text
        return part, selected, settings.destination.chat_id, text

    def _attempt(self, prepared, now):
        part, rows, chat_id, text = prepared
        manual = bool(part["manual_pending"])
        number = part["automatic_attempts"] + (not manual)
        if not manual and number > MAX_AUTOMATIC_ATTEMPTS:
            return False
        attempt_id = str(uuid4())
        # Invalid injected jitter cannot lose a known acceptance after I/O.
        delay = self._delay(number)
        with self.store.transaction() as db:
            ordinal = db.execute(
                "SELECT count(*)+1 FROM dm_delivery_attempts WHERE part_id=?", (part["part_id"],)
            ).fetchone()[0]
            db.execute(
                "INSERT INTO dm_delivery_attempts VALUES (?,?,?,?,?,NULL,'started',?,NULL,?)",
                (
                    attempt_id,
                    part["part_id"],
                    ordinal,
                    part["epoch"],
                    _stamp(now),
                    int(manual),
                    _stamp(now + timedelta(seconds=delay)),
                ),
            )
            db.execute(
                "UPDATE dm_delivery_parts SET state='inflight',automatic_attempts=?,manual_pending=0 WHERE part_id=?",
                (number, part["part_id"]),
            )
            for row in rows:
                db.execute(
                    "INSERT INTO dm_delivery_attempt_members VALUES (?,?)",
                    (attempt_id, row["occurrence_id"]),
                )
                db.execute(
                    "UPDATE dm_delivery_occurrences SET state='inflight' WHERE occurrence_id=?",
                    (row["occurrence_id"],),
                )
            self._fault("attempt_before_commit")
        self._fault("attempt_committed")
        # Recheck after durable intent. Revocations/source changes during the
        # commit interval must not expose the already-rendered body.
        refreshed_at = self._now()
        # Aging is visibility-only, but it must be persisted before rendering.
        # The attempt is already durable: retain its membership/identity/budget
        # and use historical wording if its capture deadline crossed at commit.
        self.store.age_records(now=refreshed_at)
        refreshed = self._prepare(part["part_id"], refreshed_at)
        if refreshed is None:
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE dm_delivery_attempts SET outcome='not_sent',finished_at=?,next_attempt_at=NULL WHERE attempt_id=?",
                    (_stamp(self._now()), attempt_id),
                )
                retry_state = (
                    "retry" if not manual and number < MAX_AUTOMATIC_ATTEMPTS else "failed"
                )
                db.execute(
                    "UPDATE dm_delivery_parts SET state=?,next_attempt_at=? WHERE part_id=?",
                    (retry_state, _stamp(now + timedelta(seconds=delay)), part["part_id"]),
                )
                for row in rows:
                    db.execute(
                        "UPDATE dm_delivery_occurrences SET state='queued' WHERE occurrence_id=? AND state='inflight'",
                        (row["occurrence_id"],),
                    )
            return False
        _, refreshed_rows, chat_id, text = refreshed
        if {r["occurrence_id"] for r in refreshed_rows} != {r["occurrence_id"] for r in rows}:
            raise DeliveryError("attempt_membership_changed")
        try:
            result = self.channel.send_message(chat_id, text)
            if not isinstance(result, TelegramResult):
                result = TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "invalid result")
        except Exception:  # noqa: BLE001 -- injected channel can fail after provider submission
            result = TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "channel exception")
        self._fault("provider_returned")
        finished = self._now()
        accepted = result.outcome == TelegramOutcome.ACCEPTED
        ambiguous = result.outcome == TelegramOutcome.AMBIGUOUS_OUTCOME
        suspend = result.outcome in {
            TelegramOutcome.AUTH_FAILURE,
            TelegramOutcome.RECIPIENT_FAILURE,
        }
        outcome = "outcome_unknown" if ambiguous else result.outcome.value
        retry = not accepted and not suspend and not manual and number < MAX_AUTOMATIC_ATTEMPTS
        deadline = finished + timedelta(seconds=max(delay, result.retry_after or 0))
        state = (
            "accepted"
            if accepted
            else "retry"
            if retry
            else "outcome_unknown"
            if ambiguous
            else "failed"
        )
        with self.store.transaction() as db:
            db.execute(
                "UPDATE dm_delivery_attempts SET outcome=?,finished_at=?,provider_message_id=?,next_attempt_at=? WHERE attempt_id=?",
                (
                    outcome,
                    _stamp(finished),
                    result.provider_message_id,
                    _stamp(deadline) if retry else None,
                    attempt_id,
                ),
            )
            db.execute(
                "UPDATE dm_delivery_parts SET state=?,next_attempt_at=? WHERE part_id=?",
                (state, _stamp(deadline) if retry else None, part["part_id"]),
            )
            for row in rows:
                db.execute(
                    "UPDATE dm_delivery_occurrences SET state=? WHERE occurrence_id=?",
                    (
                        "accepted" if accepted else "outcome_unknown" if ambiguous else "failed",
                        row["occurrence_id"],
                    ),
                )
            if suspend or result.outcome == TelegramOutcome.RATE_LIMITED:
                db.execute(
                    "INSERT INTO dm_delivery_routes VALUES (?,?,?,?) ON CONFLICT(epoch,generation) "
                    "DO UPDATE SET blocked_until=excluded.blocked_until,suspended=excluded.suspended",
                    (
                        part["epoch"],
                        part["generation"],
                        _stamp(deadline) if not suspend else None,
                        int(suspend),
                    ),
                )
            self._fault("outcome_before_commit")
        self._fault("outcome_committed")
        if suspend:
            for _ in range(3):
                settings = self.store.get_settings()
                if settings.destination_generation != part["generation"]:
                    break
                try:
                    self.store.update_settings(
                        settings.revision, {"provider_suspended": True}, now=finished
                    )
                    break
                except SettingsConflict:
                    continue
        return accepted

    def tick(self, *, max_attempts: int = 20) -> TickResult:
        if type(max_attempts) is not int or not 0 <= max_attempts <= 100:
            raise DeliveryError("invalid_attempt_limit")
        with self._lock:
            if self._ticking:
                raise DeliveryError("worker_reentrant")
            self._ticking = True
            try:
                self._sync(self._now())
                self._plan(self._now())
                attempted = accepted = 0
                rows = self._rows(
                    "SELECT part_id FROM dm_delivery_parts WHERE state IN ('ready','retry') ORDER BY next_attempt_at,rowid"
                )
                for row in rows:
                    if attempted >= max_attempts:
                        break
                    now = self._now()
                    current = self._rows(
                        "SELECT next_attempt_at FROM dm_delivery_parts WHERE part_id=?",
                        (row["part_id"],),
                    )[0]
                    if (
                        current["next_attempt_at"]
                        and utc_datetime(current["next_attempt_at"]) > now
                    ):
                        continue
                    # A preceding provider call may overlap source/policy changes
                    # or an aging deadline. Reconcile before durable attempt-start
                    # so untouched aged parts return to historical batch planning.
                    self.store.age_records(now=now)
                    self._reconcile(
                        now, self.store.get_settings(), self.store.recovery_state().epoch
                    )
                    prepared = self._prepare(row["part_id"], now)
                    if prepared:
                        accepted += int(self._attempt(prepared, now))
                        attempted += 1
                return TickResult(attempted, accepted, self.next_wake_seconds())
            finally:
                self._ticking = False

    def next_wake_seconds(self) -> float:
        """Bounded monotonic runtime wait; worker owns no sleep or background loop."""
        now = self._now()
        rows = self._rows(
            "SELECT next_attempt_at FROM dm_delivery_parts WHERE state IN ('ready','retry') AND next_attempt_at IS NOT NULL"
        )
        deadlines = [utc_datetime(r["next_attempt_at"]) for r in rows]
        with self.store.read_snapshot() as db:
            due = self._state(db, "digest_due")
        if due and self.store.get_settings().delivery_mode == DeliveryMode.DIGEST:
            deadlines.append(utc_datetime(due))
        return max(0.05, min(1.0, min(((d - now).total_seconds() for d in deadlines), default=1.0)))
