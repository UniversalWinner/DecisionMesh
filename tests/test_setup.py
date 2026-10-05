from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from decision_mesh.capture import assert_owner_only, atomic_write_owner_only, write_envelope
from decision_mesh.channels.telegram import (
    BotIdentity,
    SetupMessage,
    TelegramOutcome,
    TelegramResult,
)
from decision_mesh.ingestion import SpoolImporter
from decision_mesh.secrets import SecretError
from decision_mesh.settings import DestinationIdentity, revised_settings
from decision_mesh.setup import SYNTHETIC_PREVIEW, SetupError, SetupService
from decision_mesh.storage import SQLiteStore

NOW = datetime(2026, 10, 4, 10, tzinfo=UTC)
TOKEN = SecretStr("123456:" + "A" * 35)


class Secrets:
    def __init__(self):
        self.token = None
        self.version = None
        self.failed = False
        self.counter = 0

    def verify(self):
        if self.failed:
            raise SecretError("synthetic_backend_failed")

    def get_token(self):
        self.verify()
        return self.token

    def get_version(self):
        self.verify()
        return self.version

    def set_token(self, token):
        self.verify()
        self.token = token
        self.counter += 1
        self.version = f"{self.counter:048x}"


class Transport:
    def __init__(self):
        self.calls = []
        self.messages = ()
        self.outcome = TelegramResult(TelegramOutcome.ACCEPTED, "provider accepted", 5)
        self.failure = None
        self.on_send = None

    def __call__(self, token):
        assert isinstance(token, SecretStr)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get_me(self):
        self.calls.append("getMe")
        if self.failure:
            raise self.failure
        return BotIdentity(88, "test_bot")

    def get_updates(self):
        self.calls.append("getUpdates")
        if self.failure:
            raise self.failure
        return self.messages

    def send_message(self, chat, text):
        self.calls.append(("sendMessage", chat, text))
        if self.on_send:
            self.on_send()
        if self.failure:
            raise self.failure
        return self.outcome


@pytest.fixture
def context(tmp_path):
    clock = [NOW]
    vault, transport = Secrets(), Transport()
    with SQLiteStore(tmp_path / "data" / "mesh.db", now=NOW) as store:
        path = tmp_path / "data" / "setup.json"
        kwargs = {
            "secrets": vault,
            "get_settings": store.get_settings,
            "update_settings": store.update_settings,
            "publish_capture_policy": lambda: store.publish_capture_policy(
                tmp_path / "data" / "policy.json"
            ),
            "transport_factory": transport,
            "clock": lambda: clock[0],
        }
        yield SetupService(path, **kwargs), store, vault, transport, path, kwargs, clock


def preview(context, recipient=123):
    service, _, _, transport, *_ = context
    service.configure_token(TOKEN)
    code = service.discover().pairing_code
    transport.messages = (SetupMessage(recipient, SecretStr(code)),)
    view = service.pair(code)
    assert view.stage == "preview" and view.can_send_test
    return view


def accepted(context):
    view = preview(context)
    result = context[0].send_test(view.preview_id)
    assert result.stage == "test_accepted"
    return result


def test_construct_status_and_token_save_never_send(context):
    service, store, _, transport, path, *_ = context
    assert service.status().stage == "token_required" and not transport.calls
    before = store.get_settings()
    service.configure_token(TOKEN)
    assert transport.calls == ["getMe"]
    assert store.get_settings() == before
    for _ in range(3):
        assert service.status().stage == "token_validated"
    assert transport.calls == ["getMe"]
    assert_owner_only(path)
    assert TOKEN.get_secret_value() not in path.read_text() + repr(service) + repr(
        service.progress()
    )


def test_exact_preview_one_use_inactive_after_acceptance(context):
    service, store, _, transport, *_ = context
    view = preview(context)
    assert view.recipient == "123" and view.preview == SYNTHETIC_PREVIEW
    assert view.preview == (
        Path(__file__).parent / "fixtures/setup/synthetic-preview.txt"
    ).read_text().rstrip("\n")
    service.send_test("wrong")
    assert not any(isinstance(call, tuple) for call in transport.calls)
    result = service.send_test(view.preview_id)
    assert result.stage == "test_accepted" and "unknown" in result.message
    assert store.get_settings().destination == DestinationIdentity(chat_id=123, bot_id=88)
    assert not store.get_settings().channel_active and not store.current_policy().channel_active
    service.send_test(view.preview_id)
    assert sum(isinstance(call, tuple) for call in transport.calls) == 1
    proposed = revised_settings(store.get_settings(), {"channel_active": True})
    service.validate_activation(proposed)


def test_restart_resume_keeps_completed_stages_but_expires_pairing(context, tmp_path):
    service, _, _, transport, path, kwargs, _ = context
    host = tmp_path / "host.exe"
    host.write_bytes(b"synthetic")
    service.check_environment(host, "1.2.3")
    service.check_local_capture(lambda: True)
    service.configure_token(TOKEN)
    code = service.discover().pairing_code
    reopened = SetupService(path, **kwargs)
    assert not reopened.status().can_send_test
    reopened.reconcile()
    assert reopened.progress().local_capture_verified
    assert reopened.progress().native_qualification == "unverified"
    transport.messages = (SetupMessage(123, SecretStr(code)),)
    assert reopened.pair(code).stage == "token_validated"
    assert transport.calls == ["getMe"]
    reopened.check_environment(host, "1.2.4")
    assert not reopened.progress().local_capture_verified


def test_environment_does_not_treat_files_as_hook_trust(context, tmp_path):
    service = context[0]
    host = tmp_path / "codex.exe"
    host.write_bytes(b"fixture")
    (tmp_path / "hooks.json").write_text("{}")
    service.check_environment(host, "0.160.0")
    assert service.progress().hook_trust == "unverified"
    assert service.progress().native_qualification == "unverified"
    assert not service.check_local_capture(lambda: 1).local_capture_verified


@pytest.mark.parametrize(
    "changes",
    [{"local_layout": "compact"}, {"disclosure_fields": {"reason"}}, {"global_pause": True}],
)
def test_changed_settings_invalidates_exact_preview(context, changes):
    service, store, _, transport, *_ = context
    view = preview(context)
    store.update_settings(store.get_settings().revision, changes, now=NOW)
    assert not service.status().can_send_test
    service.send_test(view.preview_id)
    assert not any(isinstance(call, tuple) for call in transport.calls)
    service.reconcile_settings(store.get_settings())
    assert service.status().stage == "token_validated"


@pytest.mark.parametrize("failure", ["expired", "mismatch", "different_users"])
def test_pairing_expiry_mismatch_ambiguous_recipient(context, failure):
    service, _, _, transport, _, _, clock = context
    service.configure_token(TOKEN)
    code = service.discover().pairing_code
    transport.messages = (SetupMessage(123, SecretStr(code)),)
    if failure == "expired":
        clock[0] += timedelta(minutes=10)
    elif failure == "mismatch":
        code = "X" * 32
    else:
        transport.messages += (SetupMessage(999, SecretStr(code)),)
    view = service.pair(code)
    assert not view.can_send_test and view.stage == "pairing"
    assert not any(isinstance(call, tuple) for call in transport.calls)


@pytest.mark.parametrize(
    "outcome,stage",
    [
        (TelegramOutcome.AMBIGUOUS_OUTCOME, "test_unknown"),
        (TelegramOutcome.DEFINITE_FAILURE, "test_failed"),
        (TelegramOutcome.AUTH_FAILURE, "test_failed"),
        (TelegramOutcome.RATE_LIMITED, "test_failed"),
    ],
)
def test_test_failure_never_activates_or_retries(context, outcome, stage):
    service, store, _, transport, path, kwargs, _ = context
    view = preview(context)
    transport.outcome = TelegramResult(outcome, "synthetic outcome")
    assert service.send_test(view.preview_id).stage == stage
    assert not store.get_settings().channel_active
    reopened = SetupService(path, **kwargs)
    assert reopened.reconcile().stage == stage
    assert sum(isinstance(call, tuple) for call in transport.calls) == 1


def test_crash_after_durable_send_marker_is_unknown_and_never_replayed(context):
    service, store, _, transport, path, kwargs, _ = context
    view = preview(context)
    transport.on_send = lambda: (_ for _ in ()).throw(SystemExit("synthetic crash"))
    with pytest.raises(SystemExit):
        service.send_test(view.preview_id)
    assert service.progress().stage == "test_sending"
    reopened = SetupService(path, **kwargs)
    assert reopened.reconcile().stage == "test_unknown"
    assert not store.get_settings().channel_active
    assert sum(isinstance(call, tuple) for call in transport.calls) == 1


def test_accepted_restart_requires_same_verified_credential_and_recipient(context):
    _service, store, vault, _, path, kwargs, _ = context
    accepted(context)
    reopened = SetupService(path, **kwargs)
    assert reopened.reconcile().stage == "test_accepted"
    settings = store.get_settings()
    reopened.validate_activation(revised_settings(settings, {"channel_active": True}))
    with pytest.raises(SetupError):
        reopened.validate_activation(
            revised_settings(
                settings,
                {
                    "channel_active": True,
                    "destination": DestinationIdentity(chat_id=999, bot_id=88),
                },
            )
        )
    vault.set_token(TOKEN)
    with pytest.raises(SetupError):
        reopened.validate_activation(revised_settings(settings, {"channel_active": True}))
    assert reopened.reconcile().stage == "credentials_unavailable"


def test_backend_loss_disables_route_preserves_local_store(context):
    service, store, vault, _, *_ = context
    accepted(context)
    current = store.get_settings()
    store.update_settings(current.revision, {"channel_active": True}, now=NOW)
    old = store.current_policy()
    vault.failed = True
    service.reconcile()
    current = store.get_settings()
    assert (
        not current.channel_active and current.destination_generation > old.destination_generation
    )
    assert not old.permits_route(current)
    assert store.list_records() == ()


def test_replacing_active_token_revokes_old_generation_without_send(context):
    service, store, _, transport, *_ = context
    accepted(context)
    current = store.get_settings()
    store.update_settings(current.revision, {"channel_active": True}, now=NOW)
    old = store.current_policy()
    count = len(transport.calls)
    service.configure_token(TOKEN)
    assert transport.calls[count:] == ["getMe"]
    assert not old.permits_route(store.get_settings())
    assert not store.get_settings().channel_active


def test_publication_failure_keeps_test_incomplete_and_no_activation(context):
    service, store, _, transport, _, kwargs, _ = context
    view = preview(context)
    service._publish = lambda: (_ for _ in ()).throw(OSError(TOKEN.get_secret_value()))
    result = service.send_test(view.preview_id)
    assert result.stage == "test_unknown" and service.progress().policy_pending
    assert not store.get_settings().channel_active
    with pytest.raises(SetupError):
        service.validate_activation(
            revised_settings(store.get_settings(), {"channel_active": True})
        )
    assert TOKEN.get_secret_value() not in repr(result)
    service._publish = kwargs["publish_capture_policy"]
    service.reconcile_settings(store.get_settings())
    assert not service.progress().policy_pending
    assert sum(isinstance(call, tuple) for call in transport.calls) == 1


def test_settings_race_after_acceptance_never_claims_ready(context):
    service, store, _, transport, *_ = context
    view = preview(context)
    transport.on_send = lambda: store.update_settings(
        store.get_settings().revision, {"global_pause": True}, now=NOW
    )
    assert service.send_test(view.preview_id).stage == "test_unknown"
    assert store.get_settings().destination is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":2}',
        b'{"unknown":"secret"}',
        b'{"stage":"test_accepted","token":"secret"}',
        b"x" * 8193,
        b'{"schema_version":1,"schema_version":1}',
    ],
)
def test_strict_bounded_resume_state(context, raw):
    _, _, _, _, path, kwargs, _ = context
    atomic_write_owner_only(path, raw)
    with pytest.raises(SetupError, match="setup_state_unavailable"):
        SetupService(path, **kwargs)


@pytest.mark.parametrize(
    "raw", [b'{"schema_version":true}', b'{"stage":"test_accepted"}', b'{"stage":"preview"}']
)
def test_resume_requires_real_stage_dependencies(context, raw):
    _, _, _, _, path, kwargs, _ = context
    atomic_write_owner_only(path, raw)
    with pytest.raises(SetupError):
        SetupService(path, **kwargs)


def test_local_synthetic_stage_verifies_actual_spool_and_committed_import(
    context, event_factory, explicit_capabilities, tmp_path
):
    service, store, *_ = context
    host = tmp_path / "fixture-host.exe"
    host.write_bytes(b"synthetic host path; never executed")
    service.check_environment(host, "fixture-version")
    store.register_source(explicit_capabilities)
    spool = tmp_path / "setup-spool"
    event = event_factory()

    def synthetic_capture():
        receipt = write_envelope(spool, event.model_dump(mode="json"))
        report = SpoolImporter(spool, explicit_capabilities, store).run_once(now=NOW)
        return report.imported == 1 and len(store.list_records()) == 1 and not receipt.path.exists()

    assert service.check_local_capture(synthetic_capture).local_capture_verified
    assert service.progress().native_qualification == "unverified"
    assert not store.get_settings().channel_active


def test_new_recipient_does_not_receive_old_capture_backlog(
    context, explicit_capabilities, event_factory
):
    service, store, _, transport, *_ = context
    accepted(context)
    store.register_source(explicit_capabilities)
    current = store.get_settings()
    store.update_settings(current.revision, {"channel_active": True}, now=NOW)
    old_policy = store.current_policy()
    event = event_factory(capture_policy_ref=old_policy.policy_ref)
    receipt = store.ingest(event, received_at=NOW)
    assert store.eligibility_after()[-1].kind == "candidate"
    view = preview(context, recipient=999)
    service.send_test(view.preview_id)
    assert not old_policy.permits_route(store.get_settings())
    assert store.eligibility_after()[-1].kind == "cancelled"
    assert store.get_record(receipt.record_id) is not None
    sends = [call for call in transport.calls if isinstance(call, tuple)]
    assert sends == [
        ("sendMessage", 123, SYNTHETIC_PREVIEW),
        ("sendMessage", 999, SYNTHETIC_PREVIEW),
    ]


def test_failed_backend_configuration_leaves_local_state_and_no_network(context):
    service, store, vault, transport, *_ = context
    vault.failed = True
    assert "failed" in service.configure_token(TOKEN).message
    assert not transport.calls and store.list_records() == ()
    assert not store.get_settings().channel_active
