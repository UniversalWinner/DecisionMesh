"""Real local integration; no native trust, browser or external recipient claims."""

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from decision_mesh.capture import atomic_write_owner_only, ensure_spool_dir
from decision_mesh.channels.telegram import TelegramOutcome, TelegramResult
from decision_mesh.producer import ExplicitProducer, enroll_producer
from decision_mesh.runtime import Runtime, RuntimeChannel
from decision_mesh.runtime_control import (
    RuntimeErrorCode,
    RuntimePaths,
    active_metadata,
    authenticate,
    open_inbox,
    read_metadata,
    stop_runtime,
)
from decision_mesh.settings import DestinationIdentity, SettingsConflict, SettingsError
from decision_mesh.storage import SQLiteStore
from decision_mesh.web import WebServiceError


def document(**changes):
    return {
        "source_request_id": "runtime-test",
        "snapshot": {"kind": "question", "title": "Choose a target", "summary": "A or B?"},
    } | changes


@pytest.fixture
def running(tmp_path):
    runtime = Runtime(tmp_path / "data", local_only=True, poll_seconds=0.05).start()
    thread = threading.Thread(target=runtime.serve)
    thread.start()
    try:
        yield runtime
    finally:
        if runtime.service:
            runtime.request_stop()
        thread.join(5)
        assert not thread.is_alive()


def test_empty_runtime_authenticates_open_and_stop_flushes(running):
    metadata = read_metadata(running.paths)
    assert metadata.port > 0 and len(metadata.secret) == 32
    assert metadata.control_secret not in repr(metadata)
    assert active_metadata(running.paths) == metadata
    opened = []
    open_inbox(running.paths, browser=lambda url: opened.append(url) or True)
    assert opened[0].startswith(metadata.origin + "/#nonce=")
    assert metadata.control_secret not in opened[0]
    assert stop_runtime(running.paths)


def test_second_runtime_cannot_write_or_replace_metadata(running):
    before = running.paths.metadata.read_bytes()
    with pytest.raises(RuntimeErrorCode, match="already_started"):
        running.start()
    with pytest.raises(RuntimeErrorCode):
        Runtime(running.paths.root, local_only=True).start()
    assert running.paths.metadata.read_bytes() == before
    assert authenticate(read_metadata(running.paths), "open").result == "ok"


def test_source_enrollment_import_replay_and_fair_importer_reuse(running):
    enrollment = enroll_producer(running.paths.producer)
    producer = ExplicitProducer(running.paths.producer, policy_path=running.paths.policy)
    receipt = producer.create(document())
    raw = receipt.path.read_bytes()
    deadline = time.monotonic() + 4
    while receipt.path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not receipt.path.exists()
    importer = running.importers[enrollment.producer_id]
    page = running.service.snapshot(now=datetime.now(UTC))
    assert page.counts.attention == 1
    assert page.records[0].evidence_class == "producer_reported"
    assert page.records[0].local_details.title == "Choose a target"
    atomic_write_owner_only(receipt.path, raw)
    running.scan_once()
    assert running.importers[enrollment.producer_id] is importer
    assert len(running.store.list_records()) == 1
    assert not receipt.path.exists()
    reference = page.records[0].short_reference
    urls = []
    open_inbox(running.paths, reference=reference, browser=lambda url: urls.append(url) or True)
    assert urls[0].endswith("&reference=" + reference)


def test_namespace_spoof_never_enrolls_itself(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    enroll_producer(paths.producer)
    producer = ExplicitProducer(paths.producer)
    receipt = producer.create(document())
    raw = json.loads(receipt.path.read_bytes())
    raw["producer_id"] = "explicit:" + "f" * 32
    atomic_write_owner_only(receipt.path, json.dumps(raw).encode())
    with Runtime(paths.root, local_only=True) as runtime:
        assert runtime.store.source_registration(raw["producer_id"]) is None
        assert runtime.store.list_records() == ()
        assert list((producer.spool_dir / ".quarantine").glob("*.bad"))


def test_metadata_rotation_and_clean_shutdown(tmp_path):
    root = tmp_path / "data"
    with Runtime(root, local_only=True) as first:
        original = first.metadata
    assert not (root / "runtime.json").exists()
    with Runtime(root, local_only=True) as second:
        assert second.metadata.instance_id != original.instance_id
        assert second.metadata.secret != original.secret


def test_snapshot_is_bounded_and_ui_mutations_do_not_change_source(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    enroll_producer(paths.producer)
    producer = ExplicitProducer(paths.producer)
    for i in range(3):
        producer.create(document(source_request_id=f"record-{i}"))
    with Runtime(paths.root, local_only=True, poll_seconds=10) as runtime:
        page = runtime.service.snapshot(now=datetime.now(UTC), limit=1)
        assert len(page.records) == 1 and page.counts.attention == 3 and page.next_cursor
        record = page.records[0]
        before = runtime.store.get_record(record.record_id).projection
        runtime.service.mark_seen(record.record_id, now=datetime.now(UTC))
        runtime.service.snooze(
            record.record_id, datetime.now(UTC) + timedelta(minutes=10), now=datetime.now(UTC)
        )
        runtime.service.set_suppressed(record.record_id, True, now=datetime.now(UTC))
        assert runtime.store.get_record(record.record_id).projection == before
        runtime.service.update_settings(0, {"local_layout": "compact"}, now=datetime.now(UTC))
        with pytest.raises(SettingsConflict):
            runtime.service.update_settings(0, {"local_layout": "friendly"}, now=datetime.now(UTC))
        with pytest.raises(SettingsError):
            runtime.service.update_settings(1, {"channel_active": True}, now=datetime.now(UTC))
        with runtime.service.delivery_gate:
            with pytest.raises(WebServiceError, match="busy"):
                runtime.service.delivery_callbacks().resume_route()
            assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 2


@pytest.mark.parametrize("broken", ["construction", "reconcile"])
def test_optional_setup_failure_disables_existing_active_route(tmp_path, monkeypatch, broken):
    import decision_mesh.runtime as module

    root = tmp_path / "data"
    with SQLiteStore(root / "decisionmesh.db") as store:
        store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )

    class BrokenSetup:
        def __init__(self, *args, **kwargs):
            if broken == "construction":
                raise ValueError("PRIVATE_SECRET")

        def reconcile(self):
            raise ValueError("PRIVATE_SECRET")

    monkeypatch.setattr(module, "SetupService", BrokenSetup)
    with Runtime(root) as runtime:
        assert runtime.service.setup is None
        assert not runtime.store.get_settings().channel_active
        assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 0
        assert "PRIVATE_SECRET" not in (root / "runtime-diagnostics.json").read_text()


def test_policy_publication_failure_keeps_local_service_and_closes_sends(tmp_path, monkeypatch):
    monkeypatch.setattr(
        SQLiteStore,
        "publish_capture_policy",
        lambda *args: (_ for _ in ()).throw(OSError("SECRET")),
    )
    with Runtime(tmp_path / "data", local_only=True) as runtime:
        assert not runtime.service.policy_ready
        assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 0
        with pytest.raises(WebServiceError):
            runtime.service.update_settings(0, {"local_layout": "compact"}, now=datetime.now(UTC))
        assert runtime.store.get_settings().local_layout == "compact"
        assert not runtime.service.policy_ready


def test_broken_enrollment_does_not_kill_local_inbox(tmp_path):
    root = tmp_path / "data"
    ensure_spool_dir(root)
    enroll_producer(root / "producer")
    atomic_write_owner_only(root / "producer" / "enrollment.json", b"invalid")
    with Runtime(root, local_only=True) as runtime:
        assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 0
        assert runtime.counters.counts["scan_failed"] >= 1


def test_provider_exception_and_cleanup_preserve_send_knowledge(tmp_path):
    with Runtime(tmp_path / "data", local_only=True) as runtime:
        service = runtime.service
        service.local_only = False
        service.setup = SimpleNamespace(validate_activation=lambda _: None)
        runtime.store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )

        class Transport:
            def __init__(self, *_args, **_kwargs):
                pass

            def send_message(self, *_args):
                # A second store operation completes during the provider call.
                runtime.store.set_record_metadata("absent", now=datetime.now(UTC))

            def close(self):
                raise ValueError("SECRET")

        channel = RuntimeChannel(
            service,
            SimpleNamespace(get_token=lambda: SecretStr("test")),
            transport_factory=Transport,
        )
        assert channel.send_message(42, "test").outcome == TelegramOutcome.AMBIGUOUS_OUTCOME
        Transport.send_message = lambda *_args: TelegramResult(
            TelegramOutcome.ACCEPTED, "accepted", provider_message_id=9
        )
        assert channel.send_message(42, "test").outcome == TelegramOutcome.ACCEPTED
        service.policy_ready = False
        assert channel.send_message(42, "test").outcome == TelegramOutcome.AUTH_FAILURE


def test_disposable_process_race_open_auth_stop(tmp_path):
    """Actual Windows process smoke, local-only and browser callback only."""
    root = tmp_path / "process"
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    args = [sys.executable, "-m", "decision_mesh", "run", "--data-dir", str(root), "--local-only"]
    options = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": env}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    process = subprocess.Popen(args, **options)
    paths = RuntimePaths(root)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                metadata = active_metadata(paths)
                if metadata and authenticate(metadata, "open"):
                    break
            except RuntimeErrorCode:
                pass
            if process.poll() is not None:
                pytest.fail("runtime process ended before readiness")
            time.sleep(0.05)
        else:
            pytest.fail("runtime readiness timed out")
        rival = subprocess.run(args, capture_output=True, env=env, timeout=5, check=False)
        assert rival.returncode == 1
        urls = []
        open_inbox(paths, browser=lambda url: urls.append(url) or True)
        assert len(urls) == 1
        assert stop_runtime(paths)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr.decode()
        assert not stdout and not stderr
        assert not paths.metadata.exists()
        assert active_metadata(paths) is None
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def test_restart_demotes_synthetic_native_confirmation(
    tmp_path, native_capabilities, event_factory, now
):
    root = tmp_path / "data"
    with SQLiteStore(root / "decisionmesh.db", now=now) as store:
        store.register_source(native_capabilities, enabled=True, qualified=True)
        receipt = store.ingest(
            event_factory(native=True, current=True, restored=True), received_at=now
        )
        assert store.get_record(receipt.record_id).projection.current_confirmed
    with Runtime(root, local_only=True, clock=lambda: now + timedelta(seconds=5)) as runtime:
        record = runtime.store.get_record(receipt.record_id).projection
        assert not record.current_confirmed and record.last_known_pending
        assert not runtime.importers  # No real native adapter is silently enabled.


def test_stop_restart_keeps_pending_and_unknown_attempt_identity(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    enroll_producer(paths.producer)

    class UnknownChannel:
        def send_message(self, *_args):
            raise OSError("submission may have occurred")

    with Runtime(paths.root, local_only=True, channel=UnknownChannel(), poll_seconds=10) as runtime:
        runtime.store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )
        runtime.service.publish_policy()
        producer = ExplicitProducer(paths.producer, policy_path=paths.policy)
        producer.create(document())
        runtime.scan_once()
        with runtime.service.delivery_gate:
            runtime.delivery.tick(max_attempts=1)
        pending = runtime.store.list_records()[0]
        first = runtime.delivery.occurrence_page().occurrences[0]
        assert first.status == "retry" and first.attempts == 1 and first.duplicate_possible
        assert runtime.delivery.attempts(first.occurrence_id)[0].outcome == "outcome_unknown"
    with Runtime(paths.root, local_only=True, channel=UnknownChannel()) as reopened:
        record = reopened.store.get_record(pending.projection.record_id)
        assert record.projection.source_state == pending.projection.source_state
        occurrence = reopened.delivery.occurrence_page().occurrences[0]
        assert occurrence.occurrence_id == first.occurrence_id
        assert occurrence.attempts == 1 and occurrence.duplicate_possible


def test_ui_setting_and_snapshot_complete_while_provider_io_blocks(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    enroll_producer(paths.producer)
    entered, release = threading.Event(), threading.Event()

    class BlockingChannel:
        def send_message(self, *_args):
            entered.set()
            assert release.wait(5)
            return TelegramResult(TelegramOutcome.ACCEPTED, "accepted", provider_message_id=1)

    with Runtime(
        paths.root, local_only=True, channel=BlockingChannel(), poll_seconds=0.05
    ) as runtime:
        runtime.store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )
        runtime.service.publish_policy()
        ExplicitProducer(paths.producer, policy_path=paths.policy).create(document())
        runtime.scan_once()

        runtime.service.setup = SimpleNamespace(
            reconcile_settings=lambda settings: runtime.service.publish_policy(),
            validate_activation=lambda settings: None,
        )
        assert runtime.service.reconcile_configuration()
        runtime.local_only = False  # Enable only the injected fake provider worker.
        try:
            assert entered.wait(2)
            assert runtime.service.snapshot(now=datetime.now(UTC)).counts.attention == 1
            with pytest.raises(WebServiceError, match="busy"):
                runtime.service.update_settings(1, {"channel_active": False}, now=datetime.now(UTC))
            record = runtime.store.list_records()[0]
            runtime.service.mark_seen(record.projection.record_id, now=datetime.now(UTC))
            assert runtime.store.get_record(record.projection.record_id).seen
            with pytest.raises(WebServiceError, match="busy"):
                runtime.service.delivery_callbacks().include_current((record.projection.record_id,))
            runtime.request_stop()
            assert runtime.paths.metadata.exists()  # Ownership retained until I/O drains.
        finally:
            release.set()
            runtime.threads[1].join(3)
        assert runtime.delivery.occurrence_page().occurrences[0].status == "accepted"


def test_activation_validates_before_commit_and_policy_failure_is_not_success(tmp_path):
    with Runtime(tmp_path / "data", local_only=True) as runtime:
        service = runtime.service
        service.local_only = False
        runtime.store.update_settings(
            0, {"destination": DestinationIdentity(chat_id=42, bot_id=7)}, now=datetime.now(UTC)
        )
        calls = []

        class Setup:
            def validate_activation(self, candidate):
                calls.append(candidate.channel_active)
                raise ValueError("test required")

            def reconcile_settings(self, candidate):
                service.publish_policy()

        service.setup = Setup()
        with pytest.raises(ValueError):
            service.update_settings(1, {"channel_active": True}, now=datetime.now(UTC))
        assert calls == [True] and not runtime.store.get_settings().channel_active
        service.setup.validate_activation = lambda candidate: calls.append(candidate.channel_active)
        assert service.update_settings(
            1, {"channel_active": True}, now=datetime.now(UTC)
        ).channel_active
        assert service.policy_ready


def test_real_process_interruption_preserves_unknown_attempt(tmp_path):
    root = tmp_path / "crash"
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    script = Path(__file__).parent / "fixtures" / "runtime" / "crash_during_send.py"
    result = subprocess.run(
        [sys.executable, str(script), str(root)],
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert result.returncode == 79, result.stderr.decode()
    assert (root / "runtime.json").exists()
    with Runtime(root, local_only=True) as runtime:
        occurrence = runtime.delivery.occurrence_page().occurrences[0]
        attempts = runtime.delivery.attempts(occurrence.occurrence_id)
        assert attempts[0].outcome == "outcome_unknown"
        assert occurrence.duplicate_possible and occurrence.attempts == 1
        assert len(runtime.store.list_records()) == 1


def test_actual_loopback_bootstrap_cookie_and_inbox_html(running):
    import http.client

    enroll_producer(running.paths.producer)
    producer = ExplicitProducer(running.paths.producer)
    producer.create(
        document(
            snapshot={
                "kind": "question",
                "title": "<script>bad()</script>",
                "summary": "Synthetic choice",
            }
        )
    )
    running.scan_once()
    reference = running.store.list_records()[0].short_reference
    metadata = read_metadata(running.paths)
    reply = authenticate(metadata, "open")
    connection = http.client.HTTPConnection("127.0.0.1", metadata.port, timeout=2)
    try:
        connection.request(
            "POST",
            "/auth/exchange",
            json.dumps({"nonce": reply.nonce, "reference": reference}),
            {"Origin": metadata.origin, "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 200
        cookie = response.getheader("Set-Cookie")
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        assert json.loads(response.read())["location"] == "/records/" + reference
        connection.request(
            "GET", "/records/" + reference, headers={"Cookie": cookie.split(";", 1)[0]}
        )
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert "&lt;script&gt;bad()&lt;/script&gt;" in body and "<script>bad()" not in body
        assert "Synthetic choice" in body
    finally:
        connection.close()


def test_real_setup_bridge_test_is_inactive_until_explicit_settings_choice(tmp_path, monkeypatch):
    import decision_mesh.runtime as module
    from decision_mesh.channels.telegram import BotIdentity, SetupMessage

    actual_setup = module.SetupService

    class Vault:
        token = version = None

        def verify(self):
            pass

        def get_version(self):
            return self.version

        def get_token(self):
            return self.token

        def set_token(self, token):
            self.token, self.version = token, "a" * 48

    class FakeTransport:
        messages = ()

        def __init__(self):
            self.sent = []

        def __call__(self, *_args, **_kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def get_me(self):
            return BotIdentity(7, "synthetic_bot")

        def get_updates(self):
            return self.messages

        def send_message(self, chat_id, text):
            self.sent.append((chat_id, text))
            return TelegramResult(TelegramOutcome.ACCEPTED, "synthetic", provider_message_id=1)

    transport = FakeTransport()
    monkeypatch.setattr(
        module,
        "SetupService",
        lambda *args, **kwargs: actual_setup(*args, **kwargs, transport_factory=transport),
    )
    with Runtime(
        tmp_path / "data", credentials=Vault(), channel=transport, poll_seconds=10
    ) as runtime:
        callbacks = runtime.service.setup_callbacks()
        callbacks.configure_token(SecretStr("123:" + "A" * 35))
        code = callbacks.discover().pairing_code
        transport.messages = (SetupMessage(42, SecretStr(code)),)
        preview = callbacks.pair(code)
        assert preview.can_send_test
        assert callbacks.send_test(preview.preview_id).stage == "test_accepted"
        settings = runtime.store.get_settings()
        assert len(transport.sent) == 1 and not settings.channel_active
        activated = runtime.service.update_settings(
            settings.revision, {"channel_active": True}, now=datetime.now(UTC)
        )
        assert activated.channel_active and runtime.service.policy_ready
        assert runtime.store.current_policy().channel_active


@pytest.mark.parametrize("mutation", ["alias", "settings"])
@pytest.mark.parametrize("boundary", ["before_publication", "publication", "after_publication"])
def test_rt2_failed_reconciliation_closes_send_gate(tmp_path, monkeypatch, mutation, boundary):
    from decision_mesh.setup import SetupError, SetupState

    root = tmp_path / "data"
    with SQLiteStore(root / "decisionmesh.db") as store:
        alias = store.project_alias("synthetic-project")
        current = store.get_settings()
        store.update_settings(
            current.revision,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )
    atomic_write_owner_only(
        root / "setup.json",
        SetupState(stage="test_accepted", bot_id=7, recipient_id=42, credential_version="a" * 48)
        .model_dump_json()
        .encode(),
    )
    vault = SimpleNamespace(
        get_version=lambda: "a" * 48, get_token=lambda: SecretStr("123:" + "A" * 35)
    )
    sent = []

    class AcceptingTransport:
        def __init__(self, *_args, **_kwargs):
            pass

        def send_message(self, *_args):
            sent.append(True)
            return TelegramResult(TelegramOutcome.ACCEPTED, "synthetic", provider_message_id=1)

        def close(self):
            pass

    with Runtime(root, credentials=vault, poll_seconds=10) as runtime:
        service = runtime.service
        channel = RuntimeChannel(service, vault, transport_factory=AcceptingTransport)
        with service.setup_gate:
            assert service.policy_ready
            save = service.setup._save

            def fail_save(**changes):
                if boundary != "publication" and changes.get("policy_pending") is (
                    boundary == "before_publication"
                ):
                    raise SetupError("synthetic_state_write_failure")
                return save(**changes)

            monkeypatch.setattr(service.setup, "_save", fail_save)
            publish = runtime.store.publish_capture_policy
            if boundary == "publication":

                def fail_publish(*args, **kwargs):
                    raise OSError("synthetic_publication_failure")

                monkeypatch.setattr(runtime.store, "publish_capture_policy", fail_publish)
            current = runtime.store.get_settings()
            with pytest.raises(SetupError):
                if mutation == "alias":
                    service.rename_alias(
                        alias.identity, "Renamed", current.revision, now=datetime.now(UTC)
                    )
                else:
                    service.update_settings(
                        current.revision, {"local_layout": "compact"}, now=datetime.now(UTC)
                    )
            assert runtime.store.get_settings().revision == current.revision + 1
            assert not service.policy_ready
            assert channel.send_message(42, "synthetic").outcome != TelegramOutcome.ACCEPTED
            assert not sent
            monkeypatch.setattr(service.setup, "_save", save)
            monkeypatch.setattr(runtime.store, "publish_capture_policy", publish)
            service.publish_policy()
            assert not service.policy_ready  # Publication cannot bypass failed reconciliation.
            service.reconcile_configuration()
            assert service.policy_ready
            assert channel.send_message(42, "synthetic").outcome == TelegramOutcome.ACCEPTED
            assert sent == [True]


def test_rt1_resume_preserves_user_state_and_creates_no_external_eligibility(tmp_path):
    from decision_mesh.setup import SetupState

    root = tmp_path / "data"
    ensure_spool_dir(root)
    existing = enroll_producer(root / "producer")
    producer = ExplicitProducer(root / "producer")
    original = producer.create(document(source_request_id="user-record"))
    with Runtime(root, local_only=True) as runtime:
        before = runtime.store.list_records()[0]
        # Even a saved active recipient must not make synthetic verification eligible.
        runtime.store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )
        runtime.service.publish_policy()
        result = runtime.service.verify_local()
        assert result["ok"] and result["scope"] == "local_runtime"
        assert not runtime.service.policy_ready  # Local-only setup has no sending authority.
        assert enroll_producer(root / "producer") == existing
        assert runtime.store.get_record(before.projection.record_id) == before
        for eligible in runtime.store.eligibility_after(limit=100):
            assert eligible.kind in {"local_only", "cancelled"}
        internal_id = enroll_producer(root / "local-verification").producer_id
        importer = runtime.importers[internal_id]
        assert runtime.service.verify_local()["ok"]
        assert runtime.importers[internal_id] is importer
        assert original.producer_id == existing.producer_id
    with Runtime(root, local_only=True) as resumed:
        assert resumed.service.verify_local()["ok"]
        state = SetupState.model_validate_json((root / "setup.json").read_bytes())
        assert state.local_capture_verified and state.environment_signature
        assert state.native_qualification == state.hook_trust == "unverified"
        assert resumed.store.get_record(before.projection.record_id).projection == replace(
            before.projection, connection_state="disconnected"
        )


def test_rt1_capture_failure_is_incomplete_and_can_resume(tmp_path, monkeypatch):
    with Runtime(tmp_path / "data", local_only=True) as runtime:
        actual = runtime.service.verify_capture
        runtime.service.verify_capture = lambda: False
        result = runtime.service.verify_local()
        assert not result["ok"] and result["environment_verified"]
        assert not runtime.service.local_setup.progress().local_capture_verified
        assert not runtime.service.policy_ready
        runtime.service.verify_capture = actual
        assert runtime.service.verify_local()["ok"]
        assert runtime.service.local_setup.progress().local_capture_verified


def test_rt1_unavailable_local_environment_does_not_claim_host_support(tmp_path, monkeypatch):
    import decision_mesh.runtime_service as service_module

    with Runtime(tmp_path / "data", local_only=True) as runtime:
        monkeypatch.setattr(service_module.sys, "executable", str(tmp_path / "missing-python.exe"))
        result = runtime.service.verify_local()
        assert not result["ok"] and not result["environment_verified"]
        assert not result["local_capture_verified"]
        assert result["native_qualification"] == result["hook_trust"] == "unverified"
        assert not runtime.paths.producer.exists()


def test_rt1_route_requires_existing_session_origin_and_csrf(running):
    client = running.app.test_client()
    origin = running.metadata.origin
    route = "/runtime/setup/verification"
    assert client.get(route, base_url=origin).status_code == 401
    assert (
        client.post(route, json={}, base_url=origin, headers={"Origin": origin}).status_code == 401
    )
    reply = authenticate(running.metadata, "open")
    assert (
        client.post(
            "/auth/exchange",
            json={"nonce": reply.nonce, "reference": None},
            base_url=origin,
            headers={"Origin": origin},
        ).status_code
        == 200
    )
    status = client.get(route, base_url=origin).json
    assert not running.paths.producer.exists()  # Status request is read-only.
    assert (
        client.post(route, json={}, base_url=origin, headers={"Origin": origin}).status_code == 403
    )
    assert (
        client.post(
            route,
            json={},
            base_url=origin,
            headers={"Origin": "https://foreign.test", "X-CSRF-Token": status["csrf"]},
        ).status_code
        == 403
    )
    response = client.post(
        route, json={}, base_url=origin, headers={"Origin": origin, "X-CSRF-Token": status["csrf"]}
    )
    assert response.status_code == 200 and response.json["local_capture_verified"]
    assert "csrf" not in response.json


@pytest.mark.parametrize("boundary", ["drop", "receipt", "record", "eligibility", "import_error"])
def test_rt1_requires_matching_commit_and_independent_readback(tmp_path, monkeypatch, boundary):
    import decision_mesh.runtime as module

    with Runtime(tmp_path / "data", local_only=True, poll_seconds=10) as runtime:
        commits = []
        ingest = runtime.store.ingest

        def count_ingest(*args, **kwargs):
            committed = ingest(*args, **kwargs)
            commits.append(committed)
            return committed

        monkeypatch.setattr(runtime.store, "ingest", count_ingest)
        if boundary in {"drop", "import_error"}:

            def fake_import(importer, **kwargs):
                if boundary == "import_error":
                    raise OSError("synthetic_import_failure")
                for path in importer.spool_dir.glob("*.json"):
                    path.unlink()
                return SimpleNamespace(imported=1)

            monkeypatch.setattr(module.SpoolImporter, "run_once", fake_import)
        elif boundary == "receipt":
            sink_ingest = module.VerificationSink.ingest

            def wrong_receipt(sink, *args, **kwargs):
                committed = sink_ingest(sink, *args, **kwargs)
                sink.receipt = replace(committed, event_id="other-event")
                return committed

            monkeypatch.setattr(module.VerificationSink, "ingest", wrong_receipt)
        elif boundary == "record":
            get_record = runtime.store.get_record

            def wrong_record(record_id):
                record = get_record(record_id)
                return replace(record, projection=replace(record.projection, request_revision=999))

            monkeypatch.setattr(runtime.store, "get_record", wrong_record)
        else:
            eligibility = runtime.store.eligibility_after

            def wrong_eligibility(*args, **kwargs):
                return tuple(replace(item, revision=999) for item in eligibility(*args, **kwargs))

            monkeypatch.setattr(runtime.store, "eligibility_after", wrong_eligibility)
        result = runtime.service.verify_local()
        assert not result["ok"] and not result["local_capture_verified"]
        assert not runtime.service.local_setup.progress().local_capture_verified
        assert not runtime.service.policy_ready
        # Verification cannot manufacture success by re-ingesting for a receipt.
        assert len(commits) == (0 if boundary in {"drop", "import_error"} else 1)
        assert all(not item.replayed for item in commits)
        assert runtime.delivery.occurrence_page().total == 0


def test_rt1_preserves_disabled_source_enrollment(tmp_path):
    root = tmp_path / "data"
    ensure_spool_dir(root)
    regular = enroll_producer(root / "producer")
    internal = enroll_producer(root / "local-verification")
    manifests = {
        name: (root / name / "enrollment.json").read_bytes()
        for name in ("producer", "local-verification")
    }
    with SQLiteStore(root / "decisionmesh.db") as store:
        for enrollment in (regular, internal):
            store.register_source(enrollment.capabilities, enabled=False)
    with Runtime(root, local_only=True) as runtime:
        result = runtime.service.verify_local()
        assert not result["ok"] and not result["local_capture_verified"]
        for enrollment in (regular, internal):
            assert not runtime.store.source_registration(enrollment.producer_id)["enabled"]
        assert not runtime.store.eligibility_after(limit=1)
        assert not runtime.importers
        assert manifests == {
            name: (root / name / "enrollment.json").read_bytes() for name in manifests
        }


def test_rt2_channel_rechecks_readiness_after_acquiring_gate(tmp_path):
    with Runtime(tmp_path / "data", local_only=True) as runtime:
        service = runtime.service
        service.local_only = False
        service.setup = SimpleNamespace(validate_activation=lambda settings: None)
        assert service.policy_ready

        def acquire(**kwargs):
            service.policy_ready = False  # A prior mutation failed just before acquisition.
            return True

        service.setup_gate = SimpleNamespace(acquire=acquire, release=lambda: None)
        sent = []
        channel = RuntimeChannel(
            service,
            SimpleNamespace(get_token=lambda: None),
            transport_factory=lambda *args, **kwargs: sent.append(True),
        )
        assert channel.send_message(42, "synthetic").outcome == TelegramOutcome.AUTH_FAILURE
        assert not sent


def test_rt1_completed_local_capture_is_independent_of_optional_policy_recovery(
    tmp_path, monkeypatch
):
    with Runtime(tmp_path / "data", local_only=True) as runtime:

        def fail_policy(*args, **kwargs):
            raise OSError("optional_policy_unavailable")

        monkeypatch.setattr(runtime.store, "publish_capture_policy", fail_policy)
        result = runtime.service.verify_local()
        assert result["ok"] and result["local_capture_verified"]
        assert not result["policy_ready"] and result["reconciliation_required"]
        assert runtime.service.local_setup.progress().local_capture_verified
        with pytest.raises(WebServiceError):
            runtime.service.reconcile_configuration()
        assert not runtime.service.policy_ready
        assert runtime.service.local_setup.progress().local_capture_verified


@pytest.fixture
def rt3_active_route(tmp_path):
    from decision_mesh.setup import SetupState

    root = tmp_path / "active"
    with SQLiteStore(root / "decisionmesh.db") as store:
        alias = store.project_alias("synthetic-rt3")
        store.update_settings(
            0,
            {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
            now=datetime.now(UTC),
        )
    atomic_write_owner_only(
        root / "setup.json",
        SetupState(stage="test_accepted", bot_id=7, recipient_id=42, credential_version="a" * 48)
        .model_dump_json()
        .encode(),
    )
    vault = SimpleNamespace(
        get_version=lambda: "a" * 48, get_token=lambda: SecretStr("123:" + "A" * 35)
    )
    sent = []

    class Transport:
        def __init__(self, *args, **kwargs):
            pass

        def send_message(self, *args):
            sent.append(True)
            return TelegramResult(TelegramOutcome.ACCEPTED, "synthetic", provider_message_id=1)

        def close(self):
            pass

    with Runtime(root, credentials=vault, poll_seconds=10) as runtime, runtime.service.setup_gate:
        assert runtime.service.policy_ready
        yield (
            runtime,
            alias,
            RuntimeChannel(runtime.service, vault, transport_factory=Transport),
            sent,
        )


@pytest.mark.parametrize("mutation", ["alias_http", "settings_service", "settings_http_race"])
def test_rt3_rejected_stale_input_preserves_valid_readiness(
    rt3_active_route, monkeypatch, mutation
):
    runtime, alias, channel, sent = rt3_active_route
    service = runtime.service
    current = runtime.store.get_settings()
    client = runtime.app.test_client()
    origin = runtime.metadata.origin
    # Obtain a real signed bootstrap via an HTTP serving thread.
    thread = threading.Thread(target=runtime.serve)
    thread.start()
    try:
        reply = authenticate(runtime.metadata, "open")
        assert (
            client.post(
                "/auth/exchange",
                json={"nonce": reply.nonce, "reference": None},
                base_url=origin,
                headers={"Origin": origin},
            ).status_code
            == 200
        )
        csrf = client.get("/runtime/setup/verification", base_url=origin).json["csrf"]
        headers = {"Origin": origin, "X-CSRF-Token": csrf}
        if mutation == "alias_http":
            response = client.post(
                "/settings/alias",
                base_url=origin,
                headers=headers,
                data={
                    "identity": alias.identity,
                    "alias": "Changed",
                    "expected_revision": current.revision - 1,
                },
            )
            assert response.status_code == 409
        elif mutation == "settings_service":
            with pytest.raises(SettingsConflict):
                service.update_settings(
                    current.revision - 1, {"local_layout": "compact"}, now=datetime.now(UTC)
                )
        else:
            update = service.update_settings

            def raced_update(expected, changes, **kwargs):
                nonlocal current
                current = update(expected, {"device_alias": "Other edit"}, **kwargs)
                return update(expected, changes, **kwargs)

            monkeypatch.setattr(service, "update_settings", raced_update)
            response = client.post(
                "/settings",
                base_url=origin,
                headers=headers,
                json={
                    "expected_revision": current.revision,
                    "changes": {"local_layout": "compact"},
                },
            )
            assert response.status_code == 409
        assert runtime.store.get_settings() == current
        assert runtime.store.lookup_project_alias(alias.identity) == alias
        assert service.policy_ready
        assert channel.send_message(42, "synthetic").outcome == TelegramOutcome.ACCEPTED
        assert sent == [True]
    finally:
        runtime.request_stop()
        thread.join(5)
        assert not thread.is_alive()


@pytest.mark.parametrize("mutation", ["alias", "settings"])
def test_rt3_actual_store_failure_still_closes_readiness(rt3_active_route, monkeypatch, mutation):
    runtime, alias, channel, sent = rt3_active_route
    current = runtime.store.get_settings()

    def fail(*args, **kwargs):
        raise OSError("synthetic_persistence_failure")

    with pytest.raises(OSError):
        if mutation == "alias":
            monkeypatch.setattr(runtime.store, "rename_alias_checked", fail)
            runtime.service.rename_alias(
                alias.identity, "New name", current.revision, now=datetime.now(UTC)
            )
        else:
            monkeypatch.setattr(runtime.store, "update_settings", fail)
            runtime.service.update_settings(
                current.revision, {"local_layout": "compact"}, now=datetime.now(UTC)
            )
    assert runtime.store.get_settings() == current
    assert not runtime.service.policy_ready
    assert channel.send_message(42, "synthetic").outcome == TelegramOutcome.AUTH_FAILURE
    assert not sent


def test_rt3_pure_invalid_input_preserves_prior_admission(rt3_active_route):
    runtime, alias, _channel, _sent = rt3_active_route
    service = runtime.service
    current = runtime.store.get_settings()
    for action in (
        lambda: service.rename_alias(alias.identity, "", current.revision, now=datetime.now(UTC)),
        lambda: service.rename_alias(
            "identity:missing", "Valid name", current.revision, now=datetime.now(UTC)
        ),
        lambda: service.update_settings(
            current.revision, {"local_layout": "invalid"}, now=datetime.now(UTC)
        ),
    ):
        with pytest.raises(SettingsError):
            action()
        assert service.policy_ready and runtime.store.get_settings() == current
    service.policy_ready = False
    with pytest.raises(SettingsConflict):
        service.update_settings(current.revision - 1, {}, now=datetime.now(UTC))
    assert not service.policy_ready


def test_rt5_start_tolerates_a_brief_readiness_probe(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from decision_mesh import runtime as runtime_module
    from decision_mesh import runtime_control

    paths = RuntimePaths(tmp_path / "probe-race")
    ensure_spool_dir(paths.root)
    probe_holds_lock, release_probe, start_attempted = (threading.Event() for _ in range(3))
    original_remove = runtime_control.remove_metadata
    original_lock = runtime_module.owner_file_lock
    failures = []
    runtime = Runtime(paths.root, local_only=True)

    def pause_probe(candidate):
        probe_holds_lock.set()
        assert release_probe.wait(2)
        return original_remove(candidate)

    @contextmanager
    def observed_lock(*args, **kwargs):
        start_attempted.set()
        with original_lock(*args, **kwargs):
            yield

    def start():
        try:
            runtime.start()
        except RuntimeErrorCode as exc:
            failures.append((type(exc).__name__, str(exc)))

    monkeypatch.setattr(runtime_control, "remove_metadata", pause_probe)
    monkeypatch.setattr(runtime_module, "owner_file_lock", observed_lock)
    probe = threading.Thread(target=runtime_control.active_metadata, args=(paths,))
    starter = threading.Thread(target=start)
    probe.start()
    try:
        assert probe_holds_lock.wait(2)
        starter.start()
        assert start_attempted.wait(2)
        time.sleep(0.05)  # Deterministically overlap a brief real rendezvous-lock probe.
        release_probe.set()
        probe.join(2)
        starter.join(5)
        assert not probe.is_alive() and not starter.is_alive()
        assert not failures, failures
        assert runtime.metadata is not None
    finally:
        release_probe.set()
        probe.join(2)
        if starter.ident is not None:
            starter.join(5)
        runtime.close()


def test_rt5_concurrent_starts_have_one_owner_and_bounded_loser(tmp_path):
    paths = RuntimePaths(tmp_path / "competing-starts")
    ensure_spool_dir(paths.root)
    contenders = [Runtime(paths.root, local_only=True) for _ in range(2)]
    barrier = threading.Barrier(2)
    winners, failures = [], []

    def start(runtime):
        barrier.wait(timeout=2)
        began = time.monotonic()
        try:
            runtime.start()
            winners.append(runtime)
        except RuntimeErrorCode as exc:
            failures.append((str(exc), time.monotonic() - began))

    threads = [threading.Thread(target=start, args=(runtime,)) for runtime in contenders]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert all(not thread.is_alive() for thread in threads)
        assert len(winners) == len(failures) == 1
        assert failures[0][0] == "runtime_already_running_or_lock_unavailable"
        assert failures[0][1] < 2
        assert active_metadata(paths) == winners[0].metadata
    finally:
        for runtime in contenders:
            runtime.close()
