"""One explicitly selected credential backend, with no discovery or fallback."""

from __future__ import annotations

import hmac
import json
import os
import secrets
from threading import RLock

from pydantic import SecretStr

SERVICE = "DecisionMesh/telegram/v1"
ACCOUNT = "bot-token"


class SecretError(RuntimeError):
    """Fixed redacted failure; backend exceptions are never forwarded."""


def _approved_backend_type():
    if os.name != "nt":
        raise SecretError("credential_backend_unavailable")
    # Do not call keyring.get_keyring(): config, entry points and chained
    # backends must never decide where an enduring token is written.
    from keyring.backends.Windows import WinVaultKeyring

    return WinVaultKeyring


class CredentialStore:
    """Only the concrete Windows Vault backend is admitted.

    Constructor performs no credential operations. verify() exercises a unique
    probe entry and verifies deletion; every operation requires that verification.
    Injecting a backend does not bypass its exact concrete type check.
    """

    def __init__(self, backend=None):
        self._backend = backend
        self._verified = False
        self._lock = RLock()

    def __repr__(self):
        return "CredentialStore(credentials=<redacted>)"

    @property
    def verified(self) -> bool:
        return self._verified

    def verify(self) -> None:
        with self._lock:
            if self._verified:
                return
            probe_account = "probe-" + secrets.token_hex(24)
            probe_service = SERVICE + "/self-test/" + secrets.token_hex(24)
            probe_value = secrets.token_urlsafe(32)
            approved = False
            succeeded = False
            cleaned = False
            try:
                expected = _approved_backend_type()
                if self._backend is None:
                    self._backend = expected()
                if type(self._backend) is not expected:
                    raise SecretError("credential_backend_unapproved")
                self._backend.persist = "local machine"
                approved = True
                self._backend.set_password(probe_service, probe_account, probe_value)
                actual = self._backend.get_password(probe_service, probe_account)
                succeeded = isinstance(actual, str) and hmac.compare_digest(actual, probe_value)
            except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
                succeeded = False
            finally:
                if approved:
                    # Also clean up if set_password wrote successfully then raised.
                    try:
                        self._backend.delete_password(probe_service, probe_account)
                        cleaned = self._backend.get_password(probe_service, probe_account) is None
                    except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
                        cleaned = False
            self._verified = succeeded and cleaned
            if not self._verified:
                raise SecretError("credential_backend_verification_failed") from None

    def get_token(self) -> SecretStr | None:
        record = self._read()
        return SecretStr(record["token"]) if record is not None else None

    def get_version(self) -> str | None:
        """Nonsecret random revision; changes on every token replacement."""
        record = self._read()
        return record["version"] if record is not None else None

    def _read(self) -> dict | None:
        with self._lock:
            self.verify()
            try:
                value = self._backend.get_password(SERVICE, ACCOUNT)
                if value is None:
                    return None
                if not isinstance(value, str) or not 1 <= len(value) <= 1024:
                    raise ValueError()
                record = json.loads(value)
                if (
                    not isinstance(record, dict)
                    or set(record) != {"token", "version"}
                    or not isinstance(record["token"], str)
                    or not 1 <= len(record["token"]) <= 256
                    or not isinstance(record["version"], str)
                    or len(record["version"]) != 48
                    or any(c not in "0123456789abcdef" for c in record["version"])
                ):
                    raise ValueError()
                return record
            except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
                self._verified = False
                raise SecretError("credential_read_failed") from None

    def set_token(self, token: SecretStr) -> None:
        with self._lock:
            if not isinstance(token, SecretStr) or not 1 <= len(token.get_secret_value()) <= 256:
                raise SecretError("credential_invalid")
            self.verify()
            try:
                encoded = json.dumps(
                    {"token": token.get_secret_value(), "version": secrets.token_hex(24)}
                )
                self._backend.set_password(SERVICE, ACCOUNT, encoded)
                actual = self._backend.get_password(SERVICE, ACCOUNT)
                if not isinstance(actual, str) or not hmac.compare_digest(actual, encoded):
                    raise ValueError()
            except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
                self._verified = False
                raise SecretError("credential_write_failed") from None

    def delete_token(self) -> None:
        with self._lock:
            self.verify()
            try:
                if self._backend.get_password(SERVICE, ACCOUNT) is not None:
                    self._backend.delete_password(SERVICE, ACCOUNT)
                if self._backend.get_password(SERVICE, ACCOUNT) is not None:
                    raise ValueError()
            except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
                self._verified = False
                raise SecretError("credential_delete_failed") from None
