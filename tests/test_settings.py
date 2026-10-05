"""Privacy generations and optimistic settings, using real SQLite persistence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError

from decision_mesh.capture import read_capture_policy
from decision_mesh.settings import (
    DestinationIdentity,
    DisclosureField,
    Settings,
    SettingsConflict,
    SettingsError,
)
from decision_mesh.storage import SQLiteStore


@pytest.fixture
def store(tmp_path, now):
    with SQLiteStore(tmp_path / "data" / "mesh.db", now=now) as value:
        yield value


def activate(store, now, **extra):
    current = store.get_settings()
    return store.update_settings(
        current.revision,
        {
            "channel_active": True,
            "destination": DestinationIdentity(chat_id=123, bot_id=456),
            **extra,
        },
        now=now,
    )


def test_default_profile():
    settings = Settings()
    assert settings.local_layout == "friendly"
    assert settings.telegram_layout == "compact"
    assert settings.delivery_mode == "immediate"
    assert settings.digest_interval_minutes == 10
    assert not settings.channel_active or settings.destination is not None
    assert not settings.channel_active and not settings.global_pause and not settings.autostart
    assert not settings.disclosure_fields


@pytest.mark.parametrize("value", [0, 1441, "10", True, 1.5])
def test_interval_bounds(value):
    with pytest.raises(ValidationError):
        Settings(digest_interval_minutes=value)


def test_settings_strict_private_destination():
    for values in ({"chat_id": -10, "bot_id": 2}, {"chat_id": 3, "bot_id": "2"}):
        with pytest.raises(ValidationError):
            DestinationIdentity(**values)
    with pytest.raises(ValidationError):
        Settings(channel_active=True)


def test_settings_reject_raw_secret_without_echo(store, now):
    with pytest.raises(SettingsError) as error:
        store.update_settings(0, {"bot_token": "SECRET-RAW-BODY"}, now=now)
    assert "SECRET" not in str(error.value)
    assert store.get_settings().revision == 0
    with pytest.raises(SettingsError):
        store.update_settings(0, {"destination_generation": 99}, now=now)


def test_concurrent_settings_only_one_stale_writer_succeeds(store, now):
    def change(value):
        try:
            return store.update_settings(0, {"digest_interval_minutes": value}, now=now)
        except SettingsConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(change, [8, 12]))
    assert sum(value is not None for value in results) == 1
    assert store.get_settings().revision == 1


def test_disable_reactivate_same_recipient_invalidates_old_grant(store, now):
    active = activate(store, now)
    original = store.current_policy()
    off = store.update_settings(active.revision, {"channel_active": False}, now=now)
    assert off.destination_generation == active.destination_generation + 1
    assert off.destination == active.destination
    on = store.update_settings(off.revision, {"channel_active": True}, now=now)
    assert on.destination_generation == off.destination_generation + 1
    assert not original.permits_route(on)
    assert store.get_policy(original.policy_ref) == original


def test_pause_suspension_and_cosmetic_changes_keep_policy_generation(store, now):
    active = activate(store, now)
    original = store.current_policy()
    updated = store.update_settings(
        active.revision,
        {
            "global_pause": True,
            "provider_suspended": True,
            "delivery_mode": "digest",
            "telegram_layout": "friendly",
            "autostart": True,
        },
        now=now,
    )
    assert updated.destination_generation == active.destination_generation
    assert original.permits_route(updated)
    assert store.current_policy() == original


def test_current_and_capture_disclosure_intersection_never_broadens(store, now):
    active = activate(store, now, disclosure_fields=["action"])
    original = store.current_policy()
    broad = store.update_settings(
        active.revision, {"disclosure_fields": ["action", "reason"]}, now=now
    )
    assert original.effective_fields(broad) == frozenset({DisclosureField.ACTION})
    assert store.current_policy().policy_ref != original.policy_ref
    narrow = store.update_settings(broad.revision, {"disclosure_fields": ["reason"]}, now=now)
    assert not original.effective_fields(narrow)
    assert original.disclosure_fields == frozenset({DisclosureField.ACTION})


def test_destination_or_bot_change_invalidates_generation(store, now):
    active = activate(store, now)
    policy = store.current_policy()
    changed = store.update_settings(
        active.revision, {"destination": {"chat_id": 123, "bot_id": 999}}, now=now
    )
    assert changed.destination_generation == active.destination_generation + 1
    assert not policy.permits_route(changed)


def test_owner_only_snapshot_capture_reader_interoperability(store, now, tmp_path):
    path = tmp_path / "capture-meta" / "policy.json"
    store.publish_capture_policy(path)
    assert read_capture_policy(path) is None
    activate(store, now)
    store.publish_capture_policy(path)
    assert read_capture_policy(path) == store.current_policy().policy_ref
    assert "123" not in path.read_text()
    assert "456" not in path.read_text()


def test_settings_historical_policies_persist_reopen(tmp_path, now):
    path = tmp_path / "data" / "mesh.db"
    with SQLiteStore(path, now=now) as first:
        expected = activate(first, now)
        policy = first.current_policy()
    with SQLiteStore(path, now=now + timedelta(seconds=1)) as reopened:
        assert reopened.get_settings() == expected
        assert reopened.current_policy() == policy
