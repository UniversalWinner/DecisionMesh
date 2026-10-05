"""Bounded inbox facade over the one serialized SQLite writer."""

from __future__ import annotations

import platform
import sys
import threading
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .secrets import CredentialStore
from .settings import SettingsConflict, SettingsError, revised_settings, validate_alias
from .setup import SetupService
from .view import record_view
from .web import (
    LOCAL_FIELDS,
    AliasView,
    DeliveryCallbacks,
    DeliveryView,
    DiagnosticsView,
    InboxCounts,
    InboxSnapshot,
    SetupCallbacks,
    WebServiceError,
)


@contextmanager
def available(lock):
    if not lock.acquire(blocking=False):
        raise WebServiceError("operation_busy")
    try:
        yield
    finally:
        lock.release()


class RuntimeService:
    def __init__(self, store, delivery, paths, *, counters, local_only=False):
        self.store, self.delivery, self.paths = store, delivery, paths
        self.counters, self.local_only = counters, local_only
        self.delivery_gate = threading.Lock()
        self.setup_gate = threading.RLock()
        self.mutation_gate = threading.RLock()
        self.setup = None
        self.stopping = False
        self.policy_ready = False
        self.verify_capture = None
        self.local_setup = None

    def _view(self, stored, now, settings):
        return record_view(
            stored,
            now=now,
            project_alias="Unknown project",
            device_alias=settings.device_alias,
            allowed_fields=LOCAL_FIELDS,
            include_local_details=True,
        )

    def snapshot(self, *, now, filter="attention", cursor=None, limit=50):
        page = self.store.inbox_page(now=now, filter=filter, cursor=cursor, limit=limit)
        summary = self.store.query_summary()
        aliases = self.store.alias_page(limit=50).aliases
        delivery_page = self.delivery.occurrence_page(limit=50)
        return InboxSnapshot(
            records=tuple(self._view(record, now, page.settings) for record in page.records),
            counts=InboxCounts(**asdict(page.counts)),
            settings=page.settings,
            next_cursor=page.next_cursor,
            source_confirmed_supported=page.source_confirmed_supported,
            diagnostics=DiagnosticsView(
                runtime=(
                    "Stopping"
                    if self.stopping
                    else "Running; diagnostics could not be persisted"
                    if self.counters.persistence_failed
                    else "Running locally"
                ),
                capture="Explicit producer enrolled"
                if summary.enabled_source_count
                else "No enabled source",
                credentials=(
                    "Disabled for this local-only runtime"
                    if self.local_only
                    else "Optional Telegram setup available"
                    if self.setup
                    else "Credentials unavailable or setup incomplete"
                ),
                last_capture_at=summary.last_capture_at,
            ),
            aliases=tuple(
                AliasView(alias.identity, alias.alias, alias.local_path) for alias in aliases
            ),
            deliveries=tuple(
                DeliveryView(
                    row.occurrence_id,
                    (row.short_reference,),
                    row.status,
                    row.attempts,
                    row.duplicate_possible,
                    row.retry_available,
                )
                for row in delivery_page.occurrences
            ),
        )

    def lookup_reference(self, reference, *, now):
        stored = self.store.lookup_reference(reference)
        return None if stored is None else self._view(stored, now, self.store.get_settings())

    def _writable(self):
        if self.stopping:
            raise WebServiceError("runtime_stopping")

    def mark_seen(self, record_id, *, now):
        self._writable()
        self.store.set_record_metadata(record_id, seen=True, now=now)

    def snooze(self, record_id, until, *, now):
        self._writable()
        self.store.set_record_metadata(record_id, snoozed_until=until, now=now)

    def set_suppressed(self, record_id, suppressed, *, now):
        self._writable()
        self.store.set_record_metadata(record_id, suppressed=suppressed, now=now)

    def setup_update_settings(self, expected_revision, changes, *, now):
        # SetupService uses this only for its own validated inactive destination.
        with self.mutation_gate:
            self._writable()
            current = self._checked_revision(expected_revision)
            revised_settings(current, changes)
            self.policy_ready = False
            return self.store.update_settings(expected_revision, changes, now=now)

    def publish_policy(self):
        self.policy_ready = False
        try:
            self.store.publish_capture_policy(self.paths.policy)
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            self.counters.bump("policy_publication_failed")
            raise WebServiceError("capture_policy_incomplete") from None

    def _reconcile(self, committed):
        self.policy_ready = False
        if self.setup:
            self.setup.reconcile_settings(committed)
        else:
            self.publish_policy()
        if self.store.get_settings() != committed:
            raise SettingsConflict("stale_settings_revision")
        if committed.channel_active:
            if self.setup is None:
                return  # No optional setup can authorize external delivery.
            self.setup.validate_activation(committed)
        self.policy_ready = True

    def reconcile_configuration(self):
        """Explicit recovery. Publication alone never reopens external admission."""
        with available(self.setup_gate), self.mutation_gate:
            self.policy_ready = False
            self._writable()
            self._reconcile(self.store.get_settings())
            return self.policy_ready

    def _checked_revision(self, expected_revision):
        try:
            current = self.store.get_settings()
        except Exception:
            self.policy_ready = False
            raise
        if type(expected_revision) is not int or current.revision != expected_revision:
            raise SettingsConflict("stale_settings_revision")
        return current

    def update_settings(self, expected_revision, changes, *, now):
        with available(self.setup_gate), self.mutation_gate:
            self._writable()
            current = self._checked_revision(expected_revision)
            candidate = revised_settings(current, changes)
            if "provider_suspended" in changes or "autostart" in changes:
                raise SettingsError("explicit_operation_required")
            # Pure no-write rejection above preserves previous admission. Credential
            # validation and every actual persistence boundary below fail closed.
            self.policy_ready = False
            if candidate.channel_active:
                if self.local_only or self.setup is None:
                    raise SettingsError("telegram_setup_required")
                self.setup.validate_activation(candidate)
            committed = self.store.update_settings(expected_revision, changes, now=now)
            self._reconcile(committed)
            return committed

    def rename_alias(self, identity, alias, expected_revision, *, now):
        with available(self.setup_gate), self.mutation_gate:
            self._writable()
            self._checked_revision(expected_revision)
            validate_alias(alias)
            if self.store.lookup_project_alias(identity) is None:
                raise SettingsError("project_alias_not_found")
            self.policy_ready = False
            committed = self.store.rename_alias_checked(
                identity, alias, expected_revision=expected_revision
            )
            self._reconcile(committed)

    def verify_local(self):
        """Explicit local-runtime check; supplies no native-host/trust evidence."""
        with available(self.setup_gate):
            self.policy_ready = False
            self._writable()
            environment_verified = False
            setup = self.setup or self.local_setup
            try:
                if setup is None:
                    setup = self.local_setup = SetupService(
                        self.paths.root / "setup.json",
                        secrets=CredentialStore(),
                        get_settings=self.store.get_settings,
                        update_settings=self.setup_update_settings,
                        publish_capture_policy=self.publish_policy,
                    )
                setup.check_environment(Path(sys.executable), platform.python_version())
                environment_verified = True
                state = setup.check_local_capture(self.verify_capture or (lambda: False))
                if not state.local_capture_verified:
                    raise WebServiceError("local_capture_incomplete")
                # Local capture evidence does not recover optional sending authority.
                # Activation or explicit reconciliation validates that separate boundary.
                return self.verification_status(setup, environment_verified=True, ok=True)
            except Exception:  # noqa: BLE001 - fixed setup result, never untrusted environment or source details
                if setup and setup.progress().environment_signature is not None:
                    try:
                        setup.check_local_capture(lambda: False)
                    except Exception:  # noqa: BLE001 - original failure remains incomplete
                        self.policy_ready = False
                return self.verification_status(
                    setup, environment_verified=environment_verified, ok=False
                )

    def verification_status(self, setup=None, *, environment_verified=None, ok=None):
        setup = setup or self.setup or self.local_setup
        state = setup.progress() if setup else None
        verified = state is not None and state.local_capture_verified
        return {
            "ok": verified if ok is None else ok,
            "scope": "local_runtime",
            "environment_verified": (state is not None and state.environment_signature is not None)
            if environment_verified is None
            else environment_verified,
            "local_capture_verified": verified if ok is not False else False,
            "native_qualification": "unverified",
            "hook_trust": "unverified",
            "policy_ready": self.policy_ready,
            "reconciliation_required": not self.policy_ready,
            "status": "local_verification_complete"
            if verified and ok is not False
            else "local_verification_incomplete",
        }

    def setup_callbacks(self):
        if self.setup is None or self.local_only:
            return None
        callbacks = self.setup.callbacks()

        def guarded(callback):
            def invoke(*args, **kwargs):
                with available(self.setup_gate):
                    self.policy_ready = False
                    self._writable()
                    return callback(*args, **kwargs)

            return invoke

        return SetupCallbacks(
            callbacks.status,
            *(
                guarded(callback) if callback else None
                for callback in (
                    callbacks.configure_token,
                    callbacks.discover,
                    callbacks.pair,
                    callbacks.send_test,
                )
            ),
        )

    def delivery_callbacks(self):
        def guarded(callback):
            def invoke(*args, **kwargs):
                with available(self.delivery_gate):
                    self._writable()
                    return callback(*args, **kwargs)

            return invoke

        def resume():
            with available(self.delivery_gate), available(self.setup_gate):
                self.policy_ready = False
                self._writable()
                result = self.delivery.resume_route()
                self._reconcile(self.store.get_settings())
                return result

        return DeliveryCallbacks(
            guarded(self.delivery.include_current), guarded(self.delivery.manual_retry), resume
        )
