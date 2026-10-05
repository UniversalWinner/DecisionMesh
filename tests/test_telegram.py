import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from decision_mesh.channels.telegram import (
    SetupPairing,
    TelegramOutcome,
    TelegramResult,
    TelegramTransport,
    create_setup_code,
    validate_get_me_payload,
)

TOKEN = "123456:" + "A" * 35
NOW = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)


class FakeResponse:
    def __init__(self, status=200, data=None):
        self.status_code, self.data = status, data

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class FakeRequester:
    def __init__(self, response=None, failure=None):
        self.response, self.failure, self.calls = response, failure, []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.failure is not None:
            raise self.failure
        return self.response


def test_accepted_is_provider_only_plaintext_fixed_origin_no_retry():
    fake = FakeRequester(
        FakeResponse(200, {"ok": True, "result": {"message_id": 17, "secret": "ignored"}})
    )
    transport = TelegramTransport(SecretStr(TOKEN), requester=fake)
    result = transport.send_message(1234, "plain <b>source text</b>")
    assert result.outcome == TelegramOutcome.ACCEPTED and result.provider_message_id == 17
    assert "device delivery and reading unknown" in result.reason
    assert len(fake.calls) == 1
    url, kwargs = fake.calls[0]
    assert url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert kwargs["follow_redirects"] is False and isinstance(kwargs["timeout"], httpx.Timeout)
    assert set(kwargs["json"]) == {"chat_id", "text", "link_preview_options"}
    assert kwargs["json"]["text"] == "plain <b>source text</b>"
    assert TOKEN not in repr(transport) + repr(result)


@pytest.mark.parametrize(
    "status,data,outcome,retry",
    [
        (400, {"ok": False, "description": "bad payload"}, TelegramOutcome.DEFINITE_FAILURE, None),
        (
            400,
            {"ok": False, "description": "Bad Request: chat not found"},
            TelegramOutcome.RECIPIENT_FAILURE,
            None,
        ),
        (401, {"description": TOKEN}, TelegramOutcome.AUTH_FAILURE, None),
        (403, {"description": TOKEN}, TelegramOutcome.RECIPIENT_FAILURE, None),
        (
            429,
            {"parameters": {"retry_after": 12}, "description": TOKEN},
            TelegramOutcome.RATE_LIMITED,
            12,
        ),
        (429, {"parameters": {"retry_after": True}}, TelegramOutcome.RATE_LIMITED, None),
        (
            200,
            {"ok": False, "error_code": 429, "parameters": {"retry_after": 4}},
            TelegramOutcome.RATE_LIMITED,
            4,
        ),
        (500, {"description": TOKEN}, TelegramOutcome.AMBIGUOUS_OUTCOME, None),
        (302, {"location": "https://evil.test/"}, TelegramOutcome.AMBIGUOUS_OUTCOME, None),
        (
            200,
            {"ok": True, "result": {"message_id": True}},
            TelegramOutcome.AMBIGUOUS_OUTCOME,
            None,
        ),
        (200, {"ok": True, "result": {"message_id": 0}}, TelegramOutcome.AMBIGUOUS_OUTCOME, None),
        (200, ValueError(TOKEN), TelegramOutcome.AMBIGUOUS_OUTCOME, None),
        (200, [], TelegramOutcome.AMBIGUOUS_OUTCOME, None),
    ],
)
def test_response_classification_no_sensitive_errors(status, data, outcome, retry, caplog):
    fake = FakeRequester(FakeResponse(status, data))
    result = TelegramTransport(TOKEN, requester=fake).send_message(1234, "message")
    assert (
        result.outcome == outcome
        and result.retry_after == retry
        and result.provider_message_id is None
    )
    assert len(fake.calls) == 1
    assert TOKEN not in repr(result) + caplog.text


@pytest.mark.parametrize(
    "error,outcome",
    [
        (httpx.ConnectTimeout(TOKEN), TelegramOutcome.DEFINITE_FAILURE),
        (httpx.ConnectError(TOKEN), TelegramOutcome.DEFINITE_FAILURE),
        (httpx.PoolTimeout(TOKEN), TelegramOutcome.DEFINITE_FAILURE),
        (httpx.ReadTimeout(TOKEN), TelegramOutcome.AMBIGUOUS_OUTCOME),
        (httpx.WriteTimeout(TOKEN), TelegramOutcome.AMBIGUOUS_OUTCOME),
        (httpx.RemoteProtocolError(TOKEN), TelegramOutcome.AMBIGUOUS_OUTCOME),
        (RuntimeError(TOKEN), TelegramOutcome.AMBIGUOUS_OUTCOME),
    ],
)
def test_io_classification_once_no_leak(error, outcome, caplog):
    fake = FakeRequester(failure=error)
    result = TelegramTransport(TOKEN, requester=fake).send_message(1234, "message")
    assert result.outcome == outcome and len(fake.calls) == 1
    assert TOKEN not in repr(result) + caplog.text


@pytest.mark.parametrize(
    "chat_id,text", [(-100, "text"), (True, "text"), (0, "text"), (1234, ""), (1234, "😀" * 1751)]
)
def test_invalid_recipient_and_message_never_send(chat_id, text):
    fake = FakeRequester()
    result = TelegramTransport(TOKEN, requester=fake).send_message(chat_id, text)
    assert result.outcome != TelegramOutcome.ACCEPTED and not fake.calls


def test_default_httpx_transport_does_not_log_token_or_follow_redirect(monkeypatch, caplog):
    created, handled = [], []

    class SafeFakeTransport:
        def __init__(self, **kwargs):
            created.append(kwargs)

        def handle_request(self, request):
            handled.append(request)
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 8}})

        def close(self):
            pass

    monkeypatch.setattr(httpx, "HTTPTransport", SafeFakeTransport)
    caplog.set_level(logging.DEBUG)
    with TelegramTransport(TOKEN) as transport:
        result = transport.send_message(1234, "safe message")
    assert result.outcome == TelegramOutcome.ACCEPTED
    assert created == [{"retries": 0, "trust_env": False}] and len(handled) == 1
    assert TOKEN not in caplog.text
    assert handled[0].extensions["timeout"]["connect"] <= 5


def test_static_constructor_errors_and_result_invariants():
    with pytest.raises(ValueError) as error:
        TelegramTransport("secret_invalid_token")
    assert "secret_invalid_token" not in str(error.value)
    with pytest.raises(ValueError):
        TelegramResult(TelegramOutcome.ACCEPTED, "accepted")
    with pytest.raises(ValueError):
        TelegramResult(TelegramOutcome.DEFINITE_FAILURE, "failed", provider_message_id=9)


def test_pure_get_me_validation():
    identity = validate_get_me_payload(
        {
            "ok": True,
            "result": {"id": 9, "is_bot": True, "username": "MyTestBot", "private": "discard"},
        }
    )
    assert identity.bot_id == 9 and identity.username == "MyTestBot"
    for payload in (
        {},
        {"ok": True, "result": {"id": True, "is_bot": True, "username": "MyTestBot"}},
        {"ok": True, "result": {"id": 9, "is_bot": False, "username": "MyTestBot"}},
    ):
        with pytest.raises(ValueError):
            validate_get_me_payload(payload)


def setup_message(code):
    return {
        "chat": {"id": 1234, "type": "private"},
        "from": {"id": 1234, "is_bot": False},
        "text": code,
    }


def test_pairing_private_user_one_use_expiry_no_code_repr():
    code = create_setup_code()
    pair = SetupPairing(code, issued_at=NOW)
    assert code.get_secret_value() not in repr(pair)
    recipient = pair.bind(setup_message(code.get_secret_value()), now=NOW + timedelta(minutes=9))
    assert recipient.chat_id == recipient.user_id == 1234
    with pytest.raises(ValueError):
        pair.bind(setup_message(code.get_secret_value()), now=NOW + timedelta(minutes=9))
    expired = SetupPairing(code, issued_at=NOW)
    with pytest.raises(ValueError):
        expired.bind(setup_message(code.get_secret_value()), now=NOW + timedelta(minutes=10))


@pytest.mark.parametrize(
    "changes",
    [
        {"chat": {"id": -100, "type": "group"}},
        {"from": {"id": 4321, "is_bot": False}},
        {"from": {"id": 1234, "is_bot": True}},
        {"forward_origin": {"type": "user"}},
        {"text": "incorrect code"},
    ],
)
def test_pairing_rejects_wrong_source(changes):
    code = "one_time_code_123456789"
    pair = SetupPairing(code, issued_at=NOW)
    message = setup_message(code)
    message.update(changes)
    with pytest.raises(ValueError):
        pair.bind(message, now=NOW)
    assert pair.bind(setup_message(code), now=NOW).chat_id == 1234


@pytest.mark.parametrize("response_kind", ["redirect", "malformed", "split_header", "accepted"])
def test_real_stack_redacts_token_headers_and_protocol_errors(response_kind, caplog):
    import httpcore
    from httpcore._backends.mock import MockBackend

    if response_kind == "redirect":
        wire = (
            "HTTP/1.1 302 Found\r\nLocation: https://api.telegram.org/bot"
            + TOKEN
            + "/sendMessage\r\nContent-Length: 0\r\n\r\n"
        ).encode()
    elif response_kind == "malformed":
        wire = ("HTTP/1.1 200 OK\r\ninvalid " + TOKEN + "\r\n\r\n").encode()
    elif response_kind == "split_header":
        # A token itself is technically a name:value header, splitting its parts.
        wire = ("HTTP/1.1 200 OK\r\n" + TOKEN + "\r\nContent-Length: 0\r\n\r\n").encode()
    else:
        body = b'{"ok":true,"result":{"message_id":29}}'
        wire = (
            "HTTP/1.1 200 OK\r\nX-Response-Token: "
            + TOKEN
            + "\r\nContent-Length: "
            + str(len(body))
            + "\r\n\r\n"
        ).encode() + body

    class CountingBackend(MockBackend):
        connections = 0

        def connect_tcp(self, *args, **kwargs):
            self.connections += 1
            return super().connect_tcp(*args, **kwargs)

    backend = CountingBackend([wire])
    caplog.set_level(logging.DEBUG)
    # Preserve actual HTTPX -> httpcore -> h11; only socket/TLS I/O is in-memory.
    with TelegramTransport(TOKEN) as transport:
        transport._requester._transport._pool.close()
        transport._requester._transport._pool = httpcore.ConnectionPool(network_backend=backend)
        result = transport.send_message(1234, "synthetic real-stack regression")
    assert backend.connections == 1
    assert "receive_response_headers" in caplog.text
    assert "<redacted>" in caplog.text
    assert TOKEN not in caplog.text + repr(result)
    assert TOKEN.partition(":")[2] not in caplog.text
    if response_kind == "accepted":
        assert result.outcome == TelegramOutcome.ACCEPTED and result.provider_message_id == 29
    else:
        assert result.outcome == TelegramOutcome.AMBIGUOUS_OUTCOME
    logging.getLogger("httpcore.http11").debug("unrelated HTTP diagnostic remains visible")
    logging.getLogger("decisionmesh.unrelated").debug("unrelated application remains visible")
    assert "unrelated HTTP diagnostic remains visible" in caplog.text
    assert "unrelated application remains visible" in caplog.text
