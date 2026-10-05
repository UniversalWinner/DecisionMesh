"""Ephemeral local-process authentication; never an authority over source requests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

Operation = Literal["open", "stop"]
TTL = 60
SESSION_TTL = 12 * 60 * 60
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$")
_INSTANCE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAC = re.compile(r"^[0-9a-f]{64}$")


class ControlError(ValueError):
    """Fixed public error, never includes authentication material."""


def _check(secret: bytes, operation: str, challenge: str, instance_id: str) -> None:
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ControlError("invalid_control_secret")
    if operation not in ("open", "stop"):
        raise ControlError("invalid_operation")
    if not isinstance(challenge, str) or not _CHALLENGE.fullmatch(challenge):
        raise ControlError("invalid_challenge")
    if not isinstance(instance_id, str) or not _INSTANCE.fullmatch(instance_id):
        raise ControlError("invalid_instance")


def _mac(secret: bytes, parts: list[str]) -> str:
    body = json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def request_mac(secret: bytes, operation: str, challenge: str, instance_id: str) -> str:
    _check(secret, operation, challenge, instance_id)
    return _mac(secret, ["decision-mesh/control/request/v1", operation, challenge, instance_id])


def response_mac(
    secret: bytes, operation: str, challenge: str, instance_id: str, nonce: str, result: str
) -> str:
    _check(secret, operation, challenge, instance_id)
    valid = (operation == "open" and result == "ok" and _TOKEN.fullmatch(nonce)) or (
        operation == "stop" and result == "stopping" and nonce == ""
    )
    if not valid:
        raise ControlError("invalid_response")
    return _mac(
        secret,
        ["decision-mesh/control/response/v1", operation, challenge, instance_id, nonce, result],
    )


@dataclass(frozen=True)
class ControlReply:
    operation: str
    challenge: str = field(repr=False)
    instance_id: str
    nonce: str = field(repr=False)
    result: str
    mac: str = field(repr=False)

    def to_dict(self) -> dict[str, str]:
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


def new_client_nonce(token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> str:
    """Generate CLI freshness locally, never accept a listener's proposed value."""
    value = token_bytes(32)
    if not isinstance(value, bytes) or len(value) != 32:
        raise ControlError("invalid_randomness")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def verify_challenge(response: dict, *, client_nonce: str, instance_id: str) -> str:
    """Reject stale-listener replay BEFORE signing its challenge.

    Both sides contribute 256 bits: a stale listener cannot replay an old signed
    reply for a new client nonce; the server cannot re-register an old challenge.
    """
    if (
        not isinstance(response, dict)
        or set(response) != {"challenge", "instance_id"}
        or not isinstance(client_nonce, str)
        or not _TOKEN.fullmatch(client_nonce)
        or response.get("instance_id") != instance_id
    ):
        raise ControlError("invalid_challenge")
    challenge = response.get("challenge")
    if (
        not isinstance(challenge, str)
        or not _CHALLENGE.fullmatch(challenge)
        or not hmac.compare_digest(challenge[:43], client_nonce)
    ):
        raise ControlError("invalid_challenge")
    return challenge


def verify_response(
    secret: bytes, response: dict, *, operation: str, challenge: str, instance_id: str
) -> ControlReply:
    """The CLI MUST call this before opening a browser or claiming a stopped runtime."""
    if not isinstance(response, dict) or set(response) != set(ControlReply.__dataclass_fields__):
        raise ControlError("invalid_response")
    if not all(isinstance(value, str) for value in response.values()):
        raise ControlError("invalid_response")
    reply = ControlReply(**response)
    if (reply.operation, reply.challenge, reply.instance_id) != (operation, challenge, instance_id):
        raise ControlError("invalid_response")
    expected = response_mac(secret, operation, challenge, instance_id, reply.nonce, reply.result)
    if not _MAC.fullmatch(reply.mac) or not hmac.compare_digest(expected, reply.mac):
        raise ControlError("invalid_response")
    return reply


@dataclass(frozen=True)
class BrowserSession:
    csrf: str = field(repr=False)
    expires_at: float


class ControlAuth:
    """Thread-safe, bounded ephemeral caches. Restart means a new object/secret.

    Monotonic deadlines do not extend when the wall clock changes. Reads neither
    renew sessions nor change user state. Capacity pressure fails closed.
    """

    def __init__(
        self,
        secret: bytes,
        instance_id: str,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
        capacity: int = 1024,
    ):
        _check(secret, "open", "A" * 43 + "." + "B" * 43, instance_id)
        if capacity < 1:
            raise ControlError("invalid_capacity")
        self._secret = secret
        self.instance_id = instance_id
        self._clock = monotonic
        self._random = token_bytes
        self._capacity = capacity
        self._challenges: dict[str, tuple[str, float]] = {}
        self._nonces: dict[str, float] = {}
        self._sessions: dict[str, BrowserSession] = {}
        self._lock = threading.RLock()

    def _token(self) -> str:
        return new_client_nonce(self._random)

    def _prune(self) -> None:
        now = self._clock()
        self._challenges = {k: v for k, v in self._challenges.items() if v[1] > now}
        self._nonces = {k: v for k, v in self._nonces.items() if v > now}
        self._sessions = {k: v for k, v in self._sessions.items() if v.expires_at > now}

    def challenge(self, operation: str, client_nonce: str | None = None) -> str:
        if operation not in ("open", "stop"):
            raise ControlError("invalid_operation")
        with self._lock:
            self._prune()
            if len(self._challenges) >= self._capacity:
                raise ControlError("authentication_busy")
            client_nonce = client_nonce if client_nonce is not None else self._token()
            if not isinstance(client_nonce, str) or not _TOKEN.fullmatch(client_nonce):
                raise ControlError("invalid_challenge")
            challenge = client_nonce + "." + self._token()
            if challenge in self._challenges:
                raise ControlError("invalid_randomness")
            self._challenges[challenge] = (operation, self._clock() + TTL)
            return challenge

    def authorize(self, operation: str, challenge: str, instance_id: str, mac: str) -> ControlReply:
        with self._lock:
            self._prune()
            expected = request_mac(self._secret, operation, challenge, instance_id)
            valid = (
                instance_id == self.instance_id
                and isinstance(mac, str)
                and _MAC.fullmatch(mac)
                and hmac.compare_digest(expected, mac)
                and self._challenges.get(challenge, (None, 0))[0] == operation
            )
            if not valid:
                raise ControlError("authentication_failed")
            del self._challenges[challenge]
            nonce, result = "", "stopping"
            if operation == "open":
                if len(self._nonces) >= self._capacity:
                    raise ControlError("authentication_busy")
                nonce, result = self._token(), "ok"
                if nonce in self._nonces:
                    raise ControlError("invalid_randomness")
                self._nonces[nonce] = self._clock() + TTL
            return ControlReply(
                operation,
                challenge,
                instance_id,
                nonce,
                result,
                response_mac(self._secret, operation, challenge, instance_id, nonce, result),
            )

    def exchange(self, nonce: str) -> tuple[str, BrowserSession]:
        with self._lock:
            self._prune()
            if not isinstance(nonce, str) or not _TOKEN.fullmatch(nonce):
                raise ControlError("authentication_failed")
            # Compare capability material in constant time, including the nonce.
            found = next((key for key in self._nonces if hmac.compare_digest(key, nonce)), None)
            if found is None:
                raise ControlError("authentication_failed")
            del self._nonces[found]
            if len(self._sessions) >= self._capacity:
                raise ControlError("authentication_busy")
            token = self._token()
            if token in self._sessions:
                raise ControlError("invalid_randomness")
            session = BrowserSession(self._token(), self._clock() + SESSION_TTL)
            self._sessions[token] = session
            return token, session

    def session(self, token: str | None) -> BrowserSession | None:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return None
        with self._lock:
            found = next((key for key in self._sessions if hmac.compare_digest(key, token)), None)
            session = self._sessions.get(found) if found else None
            return session if session and session.expires_at > self._clock() else None

    def sign_out(self) -> None:
        """Sign out all browser sessions and outstanding bootstrap authorizations."""
        with self._lock:
            self._sessions.clear()
            self._nonces.clear()
            self._challenges.clear()
