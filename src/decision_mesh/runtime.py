"""Single-process local runtime: one writer, one delivery worker, bounded imports."""

from __future__ import annotations

import secrets
import socket
import threading
import time
import uuid
from datetime import UTC, datetime

from flask import abort, g, jsonify, request
from waitress import create_server, wasyncore

from .capture import assert_owner_only, ensure_spool_dir, owner_file_lock, parse_json
from .channels.telegram import TelegramOutcome, TelegramResult, TelegramTransport
from .delivery import DeliveryWorker
from .diagnostics import RuntimeCounters
from .ingestion import SpoolImporter
from .producer import ExplicitProducer, ProducerEnrollment, enroll_producer
from .runtime_control import RuntimeErrorCode, RuntimePaths, publish_metadata, remove_metadata
from .runtime_service import RuntimeService, available
from .secrets import CredentialStore
from .setup import SetupService
from .storage import SQLiteStore
from .web import WebServiceError, create_app

# A rendezvous status probe briefly acquires the same lock. Tolerate that
# overlap for at most 250 ms; a persistent owner still fails before startup.
START_LOCK_TIMEOUT = 0.25


def utcnow():
    return datetime.now(UTC)


class VerificationSink:
    """One target receipt only; ordinary importer commit remains the mutation."""

    def __init__(self, store):
        self.store = store
        self.target = None
        self.receipt = None

    def select(self, producer_id, event_id):
        self.target = (producer_id, event_id)
        self.receipt = None

    def ingest(self, raw, *, received_at, expected_producer_id=None):
        committed = self.store.ingest(
            raw, received_at=received_at, expected_producer_id=expected_producer_id
        )
        if (committed.producer_id, committed.event_id) == self.target:
            self.receipt = committed
        return committed


class RuntimeChannel:
    """Acquire credentials only for a selected send, never cache enduring tokens."""

    def __init__(self, service, credentials, *, transport_factory=TelegramTransport):
        self.service, self.credentials = service, credentials
        self.transport_factory = transport_factory

    def send_message(self, chat_id, text):
        service = self.service
        if service.stopping:
            return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "runtime_stopping")
        try:
            if service.local_only or service.setup is None or not service.policy_ready:
                raise RuntimeErrorCode("credentials_unavailable")
            guard = available(service.setup_gate)
            guard.__enter__()
        except WebServiceError:
            return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "setup_busy")
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            return TelegramResult(TelegramOutcome.AUTH_FAILURE, "credentials_or_setup_unavailable")
        transport = None
        try:
            try:
                # Recheck after acquiring the gate: a prior reconciliation may
                # have failed between initial admission and lock acquisition.
                if not service.policy_ready or service.setup is None or service.local_only:
                    raise RuntimeErrorCode("credentials_unavailable")
                settings = service.store.get_settings()
                service.setup.validate_activation(settings)
                if not settings.channel_active or settings.destination.chat_id != chat_id:
                    raise RuntimeErrorCode("route_changed")
                token = self.credentials.get_token()
                if token is None:
                    raise RuntimeErrorCode("credentials_unavailable")
                transport = self.transport_factory(token, timeout_seconds=5)
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                return TelegramResult(
                    TelegramOutcome.AUTH_FAILURE, "credentials_or_setup_unavailable"
                )
            try:
                # No SQLite transaction or mutation lock spans provider I/O.
                return transport.send_message(chat_id, text)
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                return TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "provider_outcome_unknown")
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                    service.counters.bump("delivery_failed")
            guard.__exit__(None, None, None)


class Runtime:
    def __init__(
        self,
        data_dir,
        *,
        local_only=False,
        credentials=None,
        channel=None,
        clock=utcnow,
        poll_seconds=1.0,
    ):
        self.paths = RuntimePaths(data_dir)
        self.local_only = local_only
        self.credentials = credentials if credentials is not None else CredentialStore()
        self.injected_channel, self.clock = channel, clock
        self.poll_seconds = poll_seconds
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.lock = None
        self.store = self.service = self.delivery = self.server = None
        self.metadata = None
        self.importers = {}
        self.scan_gate = threading.Lock()
        self.verification_sink = None
        self.threads = []
        self.server_map = {}
        self.counters = None
        self._bound_socket = None
        self._stop_at = None
        self._started = False

    def start(self):
        if self._started:
            raise RuntimeErrorCode("runtime_instance_already_started")
        try:
            ensure_spool_dir(self.paths.root)
            self.lock = owner_file_lock(self.paths.lock, timeout=START_LOCK_TIMEOUT)
            self.lock.__enter__()
            self._started = True
        except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
            self.lock = None
            raise RuntimeErrorCode("runtime_already_running_or_lock_unavailable") from None
        try:
            remove_metadata(self.paths)
            self.counters = RuntimeCounters(self.paths.root / "runtime-diagnostics.json")
            self.store = SQLiteStore(self.paths.database, now=self.clock())
            self._disable_unavailable_native_sources()
            # Construct the facade first so the channel can fail closed against setup.
            self.service = RuntimeService(
                self.store, None, self.paths, counters=self.counters, local_only=self.local_only
            )
            self.service.verify_capture = self.verify_capture
            channel = (
                self.injected_channel
                if self.injected_channel is not None
                else RuntimeChannel(self.service, self.credentials)
            )
            self.delivery = DeliveryWorker(self.store, channel)
            self.service.delivery = self.delivery
            if not self.local_only:
                try:
                    self.service.setup = SetupService(
                        self.paths.root / "setup.json",
                        secrets=self.credentials,
                        get_settings=self.store.get_settings,
                        update_settings=self.service.setup_update_settings,
                        publish_capture_policy=self.service.publish_policy,
                        clock=self.clock,
                    )
                    self.service.setup.reconcile()
                except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                    self.counters.bump("setup_unavailable")
                    self.service.setup = None
                    try:
                        current = self.store.get_settings()
                        if current.channel_active:
                            self.store.update_settings(
                                current.revision, {"channel_active": False}, now=self.clock()
                            )
                    except Exception:  # noqa: BLE001 - absent setup keeps the channel closed even if this write fails
                        self.service.policy_ready = False
            try:
                self.service.reconcile_configuration()
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                self.service.policy_ready = False  # Preserve local use; the channel fails closed.
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                self.counters.bump("scan_failed")
            self._bound_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._bound_socket.bind(("127.0.0.1", 0))
            port = self._bound_socket.getsockname()[1]
            instance, secret = uuid.uuid4().hex, secrets.token_bytes(32)
            self.app = create_app(
                self.service,
                origin=f"http://127.0.0.1:{port}",
                instance_id=instance,
                control_secret=secret,
                request_stop=self.request_stop,
                setup=self.service.setup_callbacks(),
                delivery=self.service.delivery_callbacks(),
            )

            @self.app.get("/runtime/setup/verification")
            def local_verification_status():
                # Existing web guard supplies authenticated session and exact origin.
                return jsonify(self.service.verification_status() | {"csrf": g.session.csrf})

            @self.app.post("/runtime/setup/verification")
            def verify_local_setup():
                if request.get_json(silent=True) != {}:
                    abort(400)
                return jsonify(self.service.verify_local())

            @self.app.post("/runtime/setup/reconcile")
            def reconcile_local_configuration():
                if request.get_json(silent=True) != {}:
                    abort(400)
                try:
                    ready = self.service.reconcile_configuration()
                    return jsonify(
                        ok=ready,
                        status="configuration_ready" if ready else "configuration_incomplete",
                    )
                except Exception:  # noqa: BLE001 - no setup/credential exception details
                    return jsonify(ok=False, status="configuration_incomplete")

            @self.app.before_request
            def reject_stopping_requests():
                if self.service.stopping:
                    abort(503)

            self.server = create_server(
                self.app,
                sockets=[self._bound_socket],
                map=self.server_map,
                threads=4,
                connection_limit=64,
                channel_timeout=5,
                max_request_body_size=65536,
                max_request_header_size=8192,
                expose_tracebacks=False,
                log_socket_errors=False,
            )
            self.metadata = publish_metadata(self.paths, port, secret, instance_id=instance)
            self.threads = [
                threading.Thread(target=self._scan_loop, name="decisionmesh-import", daemon=True),
                threading.Thread(
                    target=self._delivery_loop, name="decisionmesh-delivery", daemon=True
                ),
            ]
            for thread in self.threads:
                thread.start()
            self.ready.set()
            return self
        except BaseException:
            self.close()
            raise

    def _disable_unavailable_native_sources(self):
        # No native adapter has a qualified installed-runtime implementation yet.
        cursor = None
        while True:
            page = self.store.source_page(cursor=cursor, limit=100)
            for source in page.sources:
                if source.enabled and source.capabilities.producer_kind == "native":
                    self.store.register_source(
                        source.capabilities,
                        enabled=False,
                        qualified=source.qualified,
                        now=self.clock(),
                    )
            cursor = page.next_cursor
            if cursor is None:
                break

    def _enroll(self):
        manifest = self.paths.producer / "enrollment.json"
        if not manifest.exists():
            return
        assert_owner_only(manifest)
        with manifest.open("rb") as stream:
            enrollment = ProducerEnrollment.model_validate(parse_json(stream.read(4097), 4096))
        capabilities = enrollment.capabilities
        registration = self.store.source_registration(capabilities.producer_id)
        if registration is None:
            # Only the controlled local enrollment file selects this namespace.
            self.store.register_source(capabilities, enabled=True, now=self.clock())
        elif not registration["enabled"]:
            self.importers.pop(capabilities.producer_id, None)
            return
        if capabilities.producer_id not in self.importers:
            self.importers[capabilities.producer_id] = SpoolImporter(
                self.paths.producer / "spool", capabilities, self.store
            )

    def scan_once(self):
        with self.scan_gate:
            self._enroll()
            for importer in self.importers.values():
                importer.run_once(now=self.clock(), limit=256)
            self.store.age_records(now=self.clock())

    def verify_capture(self):
        """Real producer/spool/import with a dedicated stable verification source."""
        with self.scan_gate:
            # Make the ordinary producer available without changing an existing enrollment.
            enroll_producer(self.paths.producer)
            self._enroll()
            root = self.paths.root / "local-verification"
            enrollment = enroll_producer(root)
            registration = self.store.source_registration(enrollment.producer_id)
            if registration is None:
                self.store.register_source(enrollment.capabilities, enabled=True, now=self.clock())
            elif not registration["enabled"]:
                return False
            importer = self.importers.get(enrollment.producer_id)
            if importer is None:
                self.verification_sink = VerificationSink(self.store)
                importer = self.importers[enrollment.producer_id] = SpoolImporter(
                    root / "spool", enrollment.capabilities, self.verification_sink
                )
            producer = ExplicitProducer(root, policy_path=None, clock=self.clock)
            document = {
                "source_request_id": "setup-check-" + uuid.uuid4().hex,
                "source_context": {
                    "producer_kind": "explicit",
                    "host": "decisionmesh",
                    "surface": "local-verification",
                },
                "snapshot": {
                    "kind": "question",
                    "title": "Synthetic local setup check",
                    "summary": "Local capture/import verification only. No native request or external send.",
                },
            }
            for operation in ("create", "withdraw"):
                captured = getattr(producer, operation)(document)
                self.verification_sink.select(captured.producer_id, captured.event_id)
                report = importer.run_once(now=self.clock(), limit=256)
                if (
                    report.imported < 1
                    or captured.path.exists()
                    or captured.capture_policy_ref is not None
                ):
                    return False
                committed = self.verification_sink.receipt
                if (
                    committed is None
                    or committed.event_id != captured.event_id
                    or committed.producer_id != captured.producer_id
                    or not committed.record_id
                ):
                    return False
                stored = self.store.get_record(committed.record_id)
                eligibility = self.store.eligibility_after(committed.sequence - 1, limit=1)
                if (
                    stored is None
                    or stored.projection.record_id != committed.record_id
                    or stored.projection.source_request_id != captured.source_request_id
                    or stored.projection.key[0] != captured.producer_id
                    or stored.projection.request_revision != captured.revision
                    or stored.projection.capture_policy_ref is not None
                    or stored.projection.evidence_class != "producer_reported"
                    or stored.projection.source_state
                    != ("unverified" if operation == "create" else "agent_withdrawn")
                    or len(eligibility) != 1
                    or eligibility[0].sequence != committed.sequence
                    or eligibility[0].record_id != committed.record_id
                    or eligibility[0].revision != captured.revision
                    or eligibility[0].kind
                    != ("local_only" if operation == "create" else "cancelled")
                ):
                    return False
                self.store.set_record_metadata(
                    committed.record_id, seen=True, suppressed=True, now=self.clock()
                )
            return True

    def _scan_loop(self):
        while not self.stop_event.wait(self.poll_seconds):
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                self.counters.bump("scan_failed")

    def _delivery_loop(self):
        while not self.stop_event.is_set():
            try:
                with self.service.delivery_gate:
                    if self.stop_event.is_set():
                        break
                    # Keep revision-checked configuration stable through final
                    # render/submission without holding a SQLite transaction.
                    if (
                        self.local_only
                        or not self.service.policy_ready
                        or not self.store.get_settings().channel_active
                    ):
                        self.delivery.tick(max_attempts=0)
                    elif self.service.setup_gate.acquire(blocking=False):
                        try:
                            self.delivery.tick(max_attempts=1)
                        finally:
                            self.service.setup_gate.release()
            except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
                self.counters.bump("delivery_failed")
            self.stop_event.wait(self.poll_seconds)

    def request_stop(self):
        # Called inside an HTTP worker; listener stays alive for reply flushing.
        self.service.stopping = True
        self._stop_at = time.monotonic()
        self.stop_event.set()

    def serve(self):
        if self.server is None:
            self.start()
        try:
            while not self.stop_event.is_set() or time.monotonic() - (self._stop_at or 0) < 0.25:
                wasyncore.loop(timeout=0.05, count=1, map=self.server_map)
        finally:
            self.close()

    def close(self):
        self.stop_event.set()
        self.ready.clear()
        if self.service:
            self.service.stopping = True
        for thread in self.threads:
            thread.join(timeout=30)
        if any(thread.is_alive() for thread in self.threads):
            # Do not release locks or close the writer beneath in-flight I/O.
            # Process exit leaves committed started attempts for unknown recovery.
            raise RuntimeErrorCode("runtime_shutdown_pending")
        if self.server:
            self.server.task_dispatcher.shutdown(timeout=30)
            if self.server.task_dispatcher.threads:
                raise RuntimeErrorCode("runtime_shutdown_pending")
            wasyncore.close_all(self.server_map)
            self.server = None
        elif self._bound_socket:
            self._bound_socket.close()
        if self.store:
            self.store.close()
            self.store = None
        if self.lock:
            remove_metadata(self.paths)
            self.lock.__exit__(None, None, None)
            self.lock = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
