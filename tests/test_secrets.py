import json
import logging
import os

import pytest
from pydantic import SecretStr

from decision_mesh import secrets as secret_module
from decision_mesh.secrets import ACCOUNT, SERVICE, CredentialStore, SecretError

TOKEN = "123456:" + "A" * 35


class Vault:
    def __init__(self):
        self.values = {}
        self.calls = []
        self.fail = None

    def set_password(self, service, account, value):
        self.calls.append(("set", service, account))
        self.values[service, account] = value
        if self.fail == "write_after":
            raise RuntimeError(TOKEN)

    def get_password(self, service, account):
        self.calls.append(("get", service, account))
        if self.fail == "read":
            raise RuntimeError(TOKEN)
        if self.fail == "mismatch":
            return "wrong"
        return self.values.get((service, account))

    def delete_password(self, service, account):
        self.calls.append(("delete", service, account))
        if self.fail == "delete":
            raise RuntimeError(TOKEN)
        self.values.pop((service, account), None)


@pytest.fixture
def approved(monkeypatch):
    monkeypatch.setattr(secret_module, "_approved_backend_type", lambda: Vault)
    return Vault()


def test_isolated_roundtrip_cleans_up_and_preserves_real_credential(approved):
    approved.values[SERVICE, ACCOUNT] = "existing"
    store = CredentialStore(approved)
    assert not approved.calls
    store.verify()
    assert store.verified and approved.values == {(SERVICE, ACCOUNT): "existing"}
    assert all(service != SERVICE for _, service, _ in approved.calls)
    assert approved.persist == "local machine"
    store.verify()
    assert len(approved.calls) == 4


@pytest.mark.parametrize("failure", ["write_after", "read", "mismatch", "delete"])
def test_verification_failure_is_closed_with_cleanup_attempt(approved, failure, caplog):
    approved.fail = failure
    store = CredentialStore(approved)
    with caplog.at_level(logging.DEBUG), pytest.raises(SecretError) as failure_info:
        store.verify()
    assert not store.verified
    assert any(call[0] == "delete" for call in approved.calls)
    assert TOKEN not in str(failure_info.value) + repr(store) + caplog.text
    if failure != "delete":
        assert not approved.values


def test_unapproved_backend_and_subclasses_never_receive_secret(approved):
    class Chained(Vault):
        pass

    for backend in (Chained(), object()):
        with pytest.raises(SecretError):
            CredentialStore(backend).set_token(SecretStr(TOKEN))
        if isinstance(backend, Chained):
            assert not backend.calls


def test_write_read_revision_delete_and_redaction(approved):
    store = CredentialStore(approved)
    store.set_token(SecretStr(TOKEN))
    first = store.get_version()
    assert store.get_token().get_secret_value() == TOKEN
    assert TOKEN not in repr(store) + repr(store.get_token())
    assert json.loads(approved.values[SERVICE, ACCOUNT])["version"] == first
    store.set_token(SecretStr(TOKEN))
    assert store.get_version() != first
    store.delete_token()
    store.delete_token()
    assert store.get_token() is None and store.get_version() is None


@pytest.mark.parametrize("value", [TOKEN, "{}", '{"token":"x","version":"bad"}', "x" * 1025])
def test_malformed_vault_record_has_no_fallback_or_input_disclosure(approved, value):
    store = CredentialStore(approved)
    store.verify()
    approved.values[SERVICE, ACCOUNT] = value
    with pytest.raises(SecretError, match="credential_read_failed"):
        store.get_token()
    assert not store.verified


def test_missing_backend_never_selects_default_keyring(monkeypatch):
    import keyring

    monkeypatch.setattr(keyring, "get_keyring", lambda: pytest.fail("backend discovery forbidden"))
    monkeypatch.setattr(
        secret_module, "_approved_backend_type", lambda: (_ for _ in ()).throw(RuntimeError(TOKEN))
    )
    with pytest.raises(SecretError, match="verification_failed"):
        CredentialStore().verify()


@pytest.mark.skipif(os.name != "nt", reason="installed Windows keyring implementation")
def test_actual_keyring_stack_fake_win32_api_roundtrip_and_logging(monkeypatch, caplog):
    from keyring.backends import Windows

    values = {}

    def read(*, Type, TargetName):
        if TargetName not in values:
            raise Windows.pywintypes.error(1168, "CredRead", "synthetic absent")
        return values[TargetName]

    def write(credential, flags):
        values[credential["TargetName"]] = credential | {
            "CredentialBlob": credential["CredentialBlob"].encode("utf-16")
        }

    def delete(*, Type, TargetName):
        values.pop(TargetName, None)

    monkeypatch.setattr(Windows.win32cred, "CredRead", read)
    monkeypatch.setattr(Windows.win32cred, "CredWrite", write)
    monkeypatch.setattr(Windows.win32cred, "CredDelete", delete)
    store = CredentialStore()
    with caplog.at_level(logging.DEBUG):
        store.set_token(SecretStr(TOKEN))
        first_version = store.get_version()
        # A fresh self-test must not move or replace the existing service entry.
        reopened = CredentialStore()
        reopened.verify()
        assert reopened.get_version() == first_version
        assert reopened.get_token().get_secret_value() == TOKEN
        assert len(values) == 1 and SERVICE in values
        assert values[SERVICE]["Persist"] == Windows.win32cred.CRED_PERSIST_LOCAL_MACHINE
        reopened.delete_token()
    assert not values and TOKEN not in caplog.text + repr(store)
