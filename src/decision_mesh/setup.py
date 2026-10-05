"""Resumable local setup. Runtime serializes these calls on its single writer.

Only configure_token/getMe, pair/getUpdates and send_test/sendMessage touch the
network, in response to explicit actions. A test never enables notifications.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets as random
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, model_validator

from .capture import assert_owner_only, atomic_write_owner_only, ensure_spool_dir, parse_json
from .channels.telegram import SetupPairing, TelegramOutcome, TelegramTransport, create_setup_code
from .secrets import CredentialStore
from .settings import DestinationIdentity, Settings
from .web import SetupCallbacks, SetupView

STATE_LIMIT = 8192
SYNTHETIC_PREVIEW = (
    "Decision Mesh setup test\n"
    "Synthetic observation only. No real request or approval is included.\n"
    "Respond to real requests in the original host.\n"
    "Provider acceptance does not prove device delivery or reading."
)


class SetupError(RuntimeError):
    """Fixed local setup error; never includes untrusted input or credentials."""


class SetupState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    schema_version: StrictInt = Field(default=1, ge=1, le=1)
    environment_signature: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    local_capture_verified: StrictBool = False
    # No API may promote a proposed hook into native support/trust evidence.
    native_qualification: Literal["unverified"] = "unverified"
    hook_trust: Literal["unverified"] = "unverified"
    autostart_verified: StrictBool = False
    bot_id: StrictInt | None = Field(default=None, gt=0, le=2**63 - 1)
    credential_version: str | None = Field(default=None, pattern=r"^[0-9a-f]{48}$")
    recipient_id: StrictInt | None = Field(default=None, gt=0, le=2**63 - 1)
    stage: Literal[
        "token_required",
        "token_validated",
        "pairing",
        "preview",
        "test_sending",
        "test_accepted",
        "test_failed",
        "test_unknown",
        "credentials_unavailable",
    ] = "token_required"
    preview_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{48}$")
    preview_revision: StrictInt | None = Field(default=None, ge=0)
    policy_pending: StrictBool = False

    @model_validator(mode="after")
    def valid_stage(self):
        tested = {"preview", "test_sending", "test_accepted", "test_failed", "test_unknown"}
        if self.stage in tested | {"token_validated", "pairing"} and (
            self.bot_id is None or self.credential_version is None
        ):
            raise ValueError("setup_identity_missing")
        if self.stage in tested and self.recipient_id is None:
            raise ValueError("setup_recipient_missing")
        if self.stage == "preview":
            if self.preview_id is None or self.preview_revision is None:
                raise ValueError("setup_preview_missing")
        elif self.preview_id is not None or self.preview_revision is not None:
            raise ValueError("setup_preview_unexpected")
        return self


class SetupService:
    """Runtime-owned facade with no worker threads and no second store writer.

    update_settings uses the public SQLiteStore signature, including keyword now.
    publish_capture_policy is a no-argument closure over the runtime's policy path.
    Call reconcile() at startup and after optional credential loss is detected.
    GET/status does not perform reconciliation, writes, verification or networking.
    """

    def __init__(
        self,
        state_path: Path | str,
        *,
        secrets: CredentialStore,
        get_settings: Callable[[], Settings],
        update_settings: Callable[..., Settings],
        publish_capture_policy: Callable[[], None],
        transport_factory=TelegramTransport,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self._path = Path(state_path).absolute()
        self._secrets = secrets
        self._get_settings = get_settings
        self._update_settings = update_settings
        self._publish = publish_capture_policy
        self._transport_factory = transport_factory
        self._clock = clock
        self._pairing = None
        self._code = None
        self._credential_ready = False
        self._message = None
        self._state = self._load()

    def __repr__(self):
        return "SetupService(credentials=<redacted>)"

    def _load(self) -> SetupState:
        try:
            ensure_spool_dir(self._path.parent)
            if not self._path.exists():
                return SetupState()
            assert_owner_only(self._path)
            with self._path.open("rb") as handle:
                raw = handle.read(STATE_LIMIT + 1)
            return SetupState.model_validate(parse_json(raw, max_bytes=STATE_LIMIT))
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_state_unavailable") from None

    def _save(self, **changes) -> None:
        try:
            candidate = SetupState.model_validate(self._state.model_dump() | changes)
            atomic_write_owner_only(
                self._path, candidate.model_dump_json().encode(), max_bytes=STATE_LIMIT
            )
            self._state = candidate
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_state_write_failed") from None

    def callbacks(self) -> SetupCallbacks:
        return SetupCallbacks(
            self.status, self.configure_token, self.discover, self.pair, self.send_test
        )

    def progress(self) -> SetupState:
        """Immutable credential-free stage evidence for runtime/doctor."""
        return self._state

    def check_environment(self, host_executable: Path | str, host_version: str) -> SetupState:
        """Local path/version dependency check, not host qualification or trust."""
        try:
            path = Path(host_executable).absolute()
            if (
                not path.is_file()
                or not isinstance(host_version, str)
                or not 1 <= len(host_version) <= 100
                or any(ord(c) < 32 for c in host_version)
            ):
                raise ValueError()
            assert_owner_only(self._path.parent)
            signature = hashlib.sha256(
                json.dumps(
                    [str(path.resolve()), host_version, str(self._path.parent.resolve())]
                ).encode()
            ).hexdigest()
            if signature != self._state.environment_signature:
                self._save(environment_signature=signature, local_capture_verified=False)
            return self._state
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_environment_unverified") from None

    def check_local_capture(self, capture_and_import: Callable[[], bool]) -> SetupState:
        """The callback must perform and verify real local synthetic spool/import.

        It returns literal True only after committed ingestion, never on mere
        helper invocation. This method does not qualify the native host.
        """
        if self._state.environment_signature is None:
            raise SetupError("setup_environment_required")
        try:
            result = capture_and_import()
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            result = False
        self._save(local_capture_verified=result is True)
        return self._state

    def _settings(self) -> Settings:
        try:
            return self._get_settings()
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_settings_unavailable") from None

    def _change_settings(self, expected: int, changes: dict) -> Settings:
        try:
            settings = self._update_settings(expected, changes, now=self._clock())
            self._save(policy_pending=True)
            self._publish()
            self._save(policy_pending=False)
            return settings
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_settings_or_policy_incomplete") from None

    def _disable(self) -> None:
        current = self._settings()
        if current.channel_active:
            self._change_settings(current.revision, {"channel_active": False})

    def reconcile(self) -> SetupView:
        """Explicit startup reconciliation; fail Telegram closed, preserve local UI."""
        self._code = None
        self._pairing = None
        try:
            version = self._secrets.get_version()
            self._credential_ready = (
                version is not None and version == self._state.credential_version
            )
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            self._credential_ready = False
        if not self._credential_ready:
            self._disable()
            self._save(stage="credentials_unavailable", preview_id=None, preview_revision=None)
        elif self._state.stage == "test_sending":
            self._disable()
            self._save(stage="test_unknown", preview_id=None, preview_revision=None)
        elif self._state.stage == "pairing":
            self._save(stage="token_validated", preview_id=None, preview_revision=None)
        elif self._state.stage == "preview":
            # Require a new challenge after restart rather than retaining pairing
            # authority whose in-memory expiry/one-use validator no longer exists.
            self._save(
                stage="token_validated", recipient_id=None, preview_id=None, preview_revision=None
            )
        current = self._settings()
        if current.channel_active:
            try:
                self.validate_activation(current)
            except SetupError:
                self._disable()
        self.reconcile_settings(self._settings())
        return self.status()

    def reconcile_settings(self, settings: Settings) -> None:
        """After any runtime settings mutation, republish and revoke stale previews.

        Caller passes the committed current settings and handles failures as
        incomplete. Store generation checks also reject stale on-disk policies.
        """
        if settings != self._settings():
            raise SetupError("setup_stale_settings")
        if self._state.preview_id and settings.revision != self._state.preview_revision:
            self._save(
                stage="token_validated", recipient_id=None, preview_id=None, preview_revision=None
            )
        try:
            self._save(policy_pending=True)
            self._publish()
            self._save(policy_pending=False)
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_policy_incomplete") from None

    def validate_activation(self, settings: Settings) -> None:
        """Mandatory BEFORE runtime accepts channel_active=True settings.

        Pass the proposed validated Settings. No network or settings write. An
        accepted setup test alone authorizes no ongoing notifications.
        """
        try:
            version = self._secrets.get_version()
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise SetupError("setup_credentials_unavailable") from None
        if (
            self._state.stage != "test_accepted"
            or self._state.policy_pending
            or version is None
            or version != self._state.credential_version
            or settings.destination is None
            or settings.destination.bot_id != self._state.bot_id
            or settings.destination.chat_id != self._state.recipient_id
        ):
            raise SetupError("setup_test_required")

    def status(self) -> SetupView:
        state = self._state
        messages = {
            "token_required": "Add a bot token to configure optional Telegram notifications.",
            "token_validated": "Bot token validated. Start private recipient pairing.",
            "pairing": "Send this one-use code in a private chat with your bot, then confirm it here. Expires in 10 minutes.",
            "preview": "Confirm the numeric private recipient and exact synthetic preview before sending.",
            "test_sending": "Setup test outcome is not yet known. No automatic resend.",
            "test_accepted": "Provider accepted the setup test; device delivery and reading are unknown. Enable Telegram separately in settings when ready.",
            "test_failed": "Setup test failed. Notifications remain off. Start pairing again to retry explicitly.",
            "test_unknown": "Setup test outcome is unknown; a duplicate is possible. Notifications remain off. Pair again only if you choose another test.",
            "credentials_unavailable": "Verified credentials unavailable. Local use remains available; Telegram is disabled.",
        }
        ready = state.stage == "preview" and self._credential_ready and not state.policy_pending
        if ready:
            # Read-only dependency guard; mutation endpoint repeats the check.
            ready = self._settings().revision == state.preview_revision
        return SetupView(
            stage=state.stage,
            message=self._message
            or (
                "Capture policy publication is incomplete."
                if state.policy_pending
                else messages[state.stage]
            ),
            recipient=str(state.recipient_id) if state.recipient_id else None,
            preview=SYNTHETIC_PREVIEW if state.stage == "preview" else None,
            preview_id=state.preview_id if ready else None,
            pairing_code=self._code.get_secret_value() if self._code else None,
            can_send_test=ready,
        )

    def configure_token(self, token: SecretStr) -> SetupView:
        self._message = None
        try:
            if not isinstance(token, SecretStr):
                raise TypeError()
            self._secrets.verify()
            with self._transport_factory(token) as transport:
                identity = transport.get_me()
            self._disable()
            # Persist invalidation before touching the enduring credential.
            self._save(
                stage="token_required",
                recipient_id=None,
                preview_id=None,
                preview_revision=None,
                bot_id=None,
                credential_version=None,
            )
            self._credential_ready = False
            self._secrets.set_token(token)
            self._save(
                stage="token_validated",
                bot_id=identity.bot_id,
                credential_version=self._secrets.get_version(),
            )
            self._credential_ready = True
            self._pairing = self._code = None
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            self._message = "Token configuration failed. No setup message was sent."
        return self.status()

    def _token(self) -> SecretStr:
        try:
            if self._secrets.get_version() != self._state.credential_version:
                raise ValueError()
            token = self._secrets.get_token()
            if token is None or self._state.bot_id is None:
                raise ValueError()
            return token
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            self._credential_ready = False
            raise SetupError("setup_credentials_unavailable") from None

    def discover(self) -> SetupView:
        self._message = None
        try:
            self._token()
            self._disable()
            self._code = create_setup_code()
            self._pairing = SetupPairing(self._code, issued_at=self._clock())
            self._save(stage="pairing", recipient_id=None, preview_id=None, preview_revision=None)
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            self._code = self._pairing = None
            self._message = "Pairing unavailable. Verify credentials and local setup."
        return self.status()

    def pair(self, code: str) -> SetupView:
        self._message = None
        try:
            if (
                self._state.stage != "pairing"
                or self._pairing is None
                or self._code is None
                or not isinstance(code, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", code)
                or not hmac.compare_digest(code, self._code.get_secret_value())
            ):
                raise ValueError()
            with self._transport_factory(self._token()) as transport:
                messages = transport.get_updates()
            matches = [m for m in messages if hmac.compare_digest(m.code.get_secret_value(), code)]
            # A code forwarded/copied to different users cannot choose a recipient
            # by update order. Require one distinct private numeric identity.
            if len({m.chat_id for m in matches}) != 1:
                raise ValueError()
            recipient = self._pairing.bind(matches[0].pairing_payload(), now=self._clock())
            self._save(
                stage="preview",
                recipient_id=recipient.chat_id,
                preview_id=random.token_hex(24),
                preview_revision=self._settings().revision,
            )
            self._code = self._pairing = None
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            self._message = "Private recipient pairing is incomplete, mismatched, or expired."
        return self.status()

    def send_test(self, preview_id: str) -> SetupView:
        self._message = None
        try:
            current = self._settings()
            if (
                self._state.stage != "preview"
                or self._state.preview_id is None
                or not isinstance(preview_id, str)
                or not re.fullmatch(r"[0-9a-f]{48}", preview_id)
                or not hmac.compare_digest(preview_id, self._state.preview_id)
                or current.revision != self._state.preview_revision
                or current.channel_active
                or self._state.policy_pending
            ):
                raise SetupError("setup_preview_required")
            token = self._token()
            recipient, bot_id = self._state.recipient_id, self._state.bot_id
            # Durable consumption BEFORE I/O prevents replay after process death.
            self._save(stage="test_sending", preview_id=None, preview_revision=None)
            with self._transport_factory(token) as transport:
                result = transport.send_message(recipient, SYNTHETIC_PREVIEW)
            if result.outcome == TelegramOutcome.ACCEPTED:
                self._change_settings(
                    current.revision,
                    {
                        "channel_active": False,
                        "destination": DestinationIdentity(chat_id=recipient, bot_id=bot_id),
                    },
                )
                self._save(stage="test_accepted")
            else:
                self._save(
                    stage="test_unknown"
                    if result.outcome == TelegramOutcome.AMBIGUOUS_OUTCOME
                    else "test_failed"
                )
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            if self._state.stage == "test_sending":
                self._save(stage="test_unknown")
                self._message = "Test or settings outcome incomplete. No automatic resend; notifications remain off."
            else:
                self._message = "Select a current exact preview before sending a setup test."
        return self.status()
