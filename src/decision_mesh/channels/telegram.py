"""Synchronous outbound-only Telegram boundary; attempts/retries belong to the worker.

The default requester uses httpx's transport interface and a per-request
httpcore trace callback to redact token-bearing headers/exceptions before DEBUG
logging. No global logger state is changed. Redirects are not followed,
environment proxies are disabled, and the transport has zero retries.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import quote

import httpx
from pydantic import SecretStr


class TelegramOutcome(StrEnum):
    ACCEPTED = "accepted"
    DEFINITE_FAILURE = "definite_failure"
    AMBIGUOUS_OUTCOME = "ambiguous_outcome"
    RATE_LIMITED = "rate_limited"
    AUTH_FAILURE = "auth_failure"
    RECIPIENT_FAILURE = "recipient_failure"


@dataclass(frozen=True)
class TelegramResult:
    outcome: TelegramOutcome
    reason: str
    provider_message_id: int | None = None
    retry_after: int | None = None

    def __post_init__(self):
        if self.outcome == TelegramOutcome.ACCEPTED:
            if type(self.provider_message_id) is not int or self.provider_message_id < 1:
                raise ValueError("accepted requires a positive provider message ID")
        elif self.provider_message_id is not None:
            raise ValueError("failure cannot contain a provider message ID")
        if self.retry_after is not None and (
            type(self.retry_after) is not int or self.retry_after < 0
        ):
            raise ValueError("retry delay must be a nonnegative integer")


class Response(Protocol):
    status_code: int

    def json(self) -> Any: ...


class Requester(Protocol):
    def post(
        self, url: str, *, json: dict, timeout: httpx.Timeout, follow_redirects: bool
    ) -> Response: ...


class _HttpxRequester:
    def __init__(self, token: SecretStr):
        self._token = token
        self._transport = httpx.HTTPTransport(retries=0, trust_env=False)

    def _redact_trace(self, event_name: str, info: dict[str, Any]) -> None:
        # httpcore invokes the request's trace extension BEFORE formatting DEBUG
        # diagnostics. Replace only trace-dictionary values, not the referenced
        # response headers/exceptions or HTTP stream. Other requests/loggers are
        # untouched. Real-stack regressions guard this installed-stack ordering.
        secret = self._token.get_secret_value()
        encoded = quote(secret, safe="")
        for key, value in tuple(info.items()):
            original = repr(value)
            diagnostic = original
            for spelling in (
                secret,
                encoded,
                encoded.replace("%3A", "%3a"),
                secret.partition(":")[2],
            ):
                diagnostic = diagnostic.replace(spelling, "<redacted>")
            if diagnostic != original:
                info[key] = diagnostic

    def post(self, url, *, json, timeout, follow_redirects):
        return self._post(url, json=json, timeout=timeout, follow_redirects=follow_redirects)

    def post_setup(self, url, *, json, timeout, follow_redirects):
        return self._post(
            url,
            json=json,
            timeout=timeout,
            follow_redirects=follow_redirects,
            max_response_bytes=256 * 1024,
        )

    def _post(self, url, *, json, timeout, follow_redirects, max_response_bytes=None):
        if follow_redirects:
            raise ValueError("redirects are disabled")
        request = httpx.Request(
            "POST",
            url,
            json=json,
            extensions={"timeout": timeout.as_dict(), "trace": self._redact_trace},
        )
        response = self._transport.handle_request(request)
        try:
            if max_response_bytes is None:
                response.read()
                return response
            body = bytearray()
            chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
            for chunk in chunks:
                if len(body) + len(chunk) > max_response_bytes:
                    raise ValueError("setup_response_too_large")
                body.extend(chunk)
            # Ignore provider encodings/headers: API JSON is parsed from a bounded
            # raw body, avoiding compressed-response amplification in setup.
            return httpx.Response(response.status_code, content=bytes(body))
        finally:
            response.close()

    def close(self):
        self._transport.close()


class TelegramTransport:
    """One call = one attempt. ACCEPTED means provider acceptance only.

    Inject a requester for tests. The caller owns injected-requester logging and
    closure. Never supply request/body/token details to operational diagnostics.
    """

    def __init__(
        self,
        token: SecretStr | str,
        *,
        requester: Requester | None = None,
        timeout_seconds: float = 10.0,
    ):
        raw = token.get_secret_value() if isinstance(token, SecretStr) else token
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,20}:[A-Za-z0-9_-]{20,128}", raw):
            raise ValueError("invalid Telegram bot token format")
        if isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 60:
            raise ValueError("Telegram timeout must be within 0 and 60 seconds")
        self._token = SecretStr(raw)
        self._owns_requester = requester is None
        self._requester = requester if requester is not None else _HttpxRequester(self._token)
        self._timeout = httpx.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds))

    def __repr__(self):
        return "TelegramTransport(token=<redacted>)"

    def close(self):
        if self._owns_requester:
            self._requester.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _setup_payload(self, method: str, payload: dict) -> Mapping:
        """One bounded setup request through the same protected requester."""
        try:
            request = (
                self._requester.post_setup
                if isinstance(self._requester, _HttpxRequester)
                else self._requester.post
            )
            response = request(
                f"https://api.telegram.org/bot{self._token.get_secret_value()}/{method}",
                json=payload,
                timeout=self._timeout,
                follow_redirects=False,
            )
            data = response.json()
            if (
                response.status_code != 200
                or not isinstance(data, Mapping)
                or data.get("ok") is not True
            ):
                raise ValueError()
            return data
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise TelegramSetupError("telegram_setup_request_failed") from None

    def get_me(self) -> BotIdentity:
        """Explicit token validation only; never sends a message."""
        try:
            return validate_get_me_payload(self._setup_payload("getMe", {}))
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors
            raise TelegramSetupError("telegram_bot_validation_failed") from None

    def get_updates(self) -> tuple[SetupMessage, ...]:
        """One non-long-polling setup read; return only private pairing inputs.

        No offset acknowledgement, loop, remote response dispatch, or history
        persistence. The service still requires a fresh one-use local challenge.
        """
        data = self._setup_payload(
            "getUpdates", {"timeout": 0, "limit": 100, "allowed_updates": ["message"]}
        )
        updates = data.get("result")
        if not isinstance(updates, list) or len(updates) > 100:
            raise TelegramSetupError("telegram_updates_invalid")
        result = []
        for update in updates:
            message = update.get("message") if isinstance(update, Mapping) else None
            if not isinstance(message, Mapping):
                continue
            chat, sender, content = message.get("chat"), message.get("from"), message.get("text")
            if (
                not isinstance(chat, Mapping)
                or not isinstance(sender, Mapping)
                or chat.get("type") != "private"
                or type(chat.get("id")) is not int
                or not 0 < chat["id"] <= 2**63 - 1
                or type(sender.get("id")) is not int
                or sender["id"] != chat["id"]
                or sender.get("is_bot") is not False
                or not isinstance(content, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", content)
                or any(
                    key in message
                    for key in (
                        "forward_origin",
                        "forward_from",
                        "forward_from_chat",
                        "forward_date",
                        "forward_sender_name",
                        "forward_from_message_id",
                        "forward_signature",
                        "is_automatic_forward",
                        "sender_chat",
                        "via_bot",
                        "via_business_bot",
                    )
                )
            ):
                continue
            result.append(SetupMessage(chat["id"], SecretStr(content)))
        return tuple(result)

    def send_message(self, chat_id: int, text: str) -> TelegramResult:
        # Telegram private user chat identifiers are positive integers.
        if type(chat_id) is not int or chat_id <= 0:
            return TelegramResult(TelegramOutcome.RECIPIENT_FAILURE, "private recipient required")
        if not isinstance(text, str) or not text:
            return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "invalid message text")
        try:
            if len(text.encode("utf-16-le")) // 2 > 3500:
                return TelegramResult(
                    TelegramOutcome.DEFINITE_FAILURE, "message exceeds safe length"
                )
        except UnicodeError:
            return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "invalid message text")
        url = f"https://api.telegram.org/bot{self._token.get_secret_value()}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "link_preview_options": {"is_disabled": True}}
        # No parse_mode, paid broadcast, remote responses or internal retry.
        try:
            response = self._requester.post(
                url, json=payload, timeout=self._timeout, follow_redirects=False
            )
        except (httpx.ConnectTimeout, httpx.ConnectError, httpx.PoolTimeout):
            return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "connection not established")
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors  # noqa: BLE001 - normalize untrusted I/O; never expose token URLs
            # Includes timeouts after transmission, partial writes, malformed I/O,
            # and injected exceptions. Exception strings/URLs are never returned.
            return TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "provider outcome unknown")
        try:
            status = response.status_code
            if type(status) is not int:
                raise ValueError("invalid status")
            try:
                data = response.json()
            except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors  # noqa: BLE001 - normalize untrusted I/O; never expose token URLs
                data = None
            return _classify(status, data)
        except Exception:  # noqa: BLE001 - redact untrusted I/O and backend errors  # noqa: BLE001 - normalize untrusted I/O; never expose token URLs
            return TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "provider outcome unknown")


def _classify(status: int, data: Any) -> TelegramResult:
    data = data if isinstance(data, Mapping) else {}
    error = data.get("error_code")
    code = status if status != 200 or type(error) is not int else error
    if code == 401:
        return TelegramResult(TelegramOutcome.AUTH_FAILURE, "bot authentication rejected")
    if code == 403:
        return TelegramResult(TelegramOutcome.RECIPIENT_FAILURE, "recipient rejected")
    if code == 429:
        parameters = data.get("parameters")
        delay = parameters.get("retry_after") if isinstance(parameters, Mapping) else None
        delay = delay if type(delay) is int and delay >= 0 else None
        return TelegramResult(
            TelegramOutcome.RATE_LIMITED, "provider rate limit", retry_after=delay
        )
    if code == 400:
        description = data.get("description")
        if isinstance(description, str) and any(
            phrase in description.lower()
            for phrase in ("chat not found", "user is deactivated", "bot was blocked")
        ):
            return TelegramResult(TelegramOutcome.RECIPIENT_FAILURE, "recipient rejected")
        return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "provider rejected request")
    if 400 <= code < 500:
        return TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "provider rejected request")
    if status == 200 and data.get("ok") is True:
        result = data.get("result")
        identifier = result.get("message_id") if isinstance(result, Mapping) else None
        if type(identifier) is int and identifier > 0:
            return TelegramResult(
                TelegramOutcome.ACCEPTED,
                "provider accepted; device delivery and reading unknown",
                provider_message_id=identifier,
            )
    return TelegramResult(TelegramOutcome.AMBIGUOUS_OUTCOME, "provider outcome unknown")


@dataclass(frozen=True)
class BotIdentity:
    bot_id: int
    username: str


class TelegramSetupError(RuntimeError):
    """Redacted setup transport failure."""


@dataclass(frozen=True)
class SetupMessage:
    chat_id: int
    code: SecretStr

    def pairing_payload(self) -> dict:
        return {
            "chat": {"type": "private", "id": self.chat_id},
            "from": {"id": self.chat_id, "is_bot": False},
            "text": self.code.get_secret_value(),
        }


def validate_get_me_payload(payload: Mapping) -> BotIdentity:
    """Pure getMe response validation. This helper performs no network calls."""
    result = payload.get("result") if isinstance(payload, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or payload.get("ok") is not True
        or not isinstance(result, Mapping)
        or result.get("is_bot") is not True
        or type(result.get("id")) is not int
        or result["id"] <= 0
        or not isinstance(result.get("username"), str)
        or not re.fullmatch(r"[A-Za-z0-9_]{5,64}", result["username"])
    ):
        raise ValueError("invalid bot identity response")
    return BotIdentity(result["id"], result["username"])


@dataclass(frozen=True)
class PrivateRecipient:
    chat_id: int
    user_id: int


class SetupPairing:
    """In-memory one-use/ten-minute pairing validator; persistence/UI follow later.

    The displayed code is supplied by the setup caller and is never retained in
    plaintext. Only a user-initiated message with matching private chat/user IDs
    can bind. Bot/group/channel/forwarded messages are rejected.
    """

    def __init__(self, code: SecretStr | str, *, issued_at: datetime):
        raw = code.get_secret_value() if isinstance(code, SecretStr) else code
        if not isinstance(raw, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", raw):
            raise ValueError("invalid pairing code")
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("pairing time requires timezone")
        self._digest = hashlib.sha256(raw.encode()).digest()
        self._issued_at = issued_at.astimezone(UTC)
        self._expires_at = self._issued_at + timedelta(minutes=10)
        self._used = False

    def __repr__(self):
        return "SetupPairing(code=<redacted>)"

    def bind(self, message: Mapping, *, now: datetime) -> PrivateRecipient:
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or self._used
            or not self._issued_at <= now < self._expires_at
        ):
            raise ValueError("pairing unavailable or expired")
        chat = message.get("chat") if isinstance(message, Mapping) else None
        sender = message.get("from") if isinstance(message, Mapping) else None
        text = message.get("text") if isinstance(message, Mapping) else None
        if (
            not isinstance(chat, Mapping)
            or not isinstance(sender, Mapping)
            or chat.get("type") != "private"
            or type(chat.get("id")) is not int
            or chat["id"] <= 0
            or sender.get("id") != chat["id"]
            or type(sender.get("id")) is not int
            or sender.get("is_bot") is not False
            or not isinstance(text, str)
            or "forward_origin" in message
            or "forward_from" in message
            or "via_bot" in message
        ):
            raise ValueError("user-initiated private recipient required")
        if not hmac.compare_digest(hashlib.sha256(text.encode()).digest(), self._digest):
            raise ValueError("pairing code mismatch")
        self._used = True
        return PrivateRecipient(chat["id"], sender["id"])


def create_setup_code() -> SecretStr:
    return SecretStr(secrets.token_urlsafe(24))
