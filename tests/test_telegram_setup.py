import json
import logging

import httpx
import pytest
from pydantic import SecretStr

from decision_mesh.channels.telegram import TelegramSetupError, TelegramTransport

TOKEN = "123456:" + "A" * 35
CODE = "random_pairing_code_123456789"


class Requester:
    def __init__(self, data, status=200):
        self.data, self.status, self.calls = data, status, []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.data, Exception):
            raise self.data
        return httpx.Response(self.status, json=self.data)


def private(chat=123, **extra):
    return {
        "message": {
            "chat": {"type": "private", "id": chat},
            "from": {"id": chat, "is_bot": False},
            "text": CODE,
            **extra,
        }
    }


def test_public_get_me_uses_same_bounded_redacted_requester():
    requester = Requester(
        {"ok": True, "result": {"id": 11, "is_bot": True, "username": "my_test_bot"}}
    )
    result = TelegramTransport(TOKEN, requester=requester).get_me()
    assert result.bot_id == 11 and result.username == "my_test_bot"
    assert len(requester.calls) == 1
    url, kwargs = requester.calls[0]
    assert url.endswith("/getMe") and kwargs["json"] == {}
    assert kwargs["follow_redirects"] is False
    assert kwargs["timeout"].read <= 10
    assert "sendMessage" not in url


def test_updates_returns_only_bounded_private_pairing_inputs():
    group = private(-100)
    group["message"]["chat"]["type"] = "group"
    mismatch = private()
    mismatch["message"]["from"]["id"] = 999
    data = {
        "ok": True,
        "result": [
            private(),
            group,
            mismatch,
            private(forward_origin={}),
            private(via_bot={}),
            {"message": TOKEN},
            private(text=TOKEN),
        ],
    }
    requester = Requester(data)
    result = TelegramTransport(TOKEN, requester=requester).get_updates()
    assert len(result) == 1 and result[0].chat_id == 123
    assert isinstance(result[0].code, SecretStr) and CODE not in repr(result)
    assert result[0].pairing_payload()["text"] == CODE
    assert requester.calls[0][1]["json"] == {
        "timeout": 0,
        "limit": 100,
        "allowed_updates": ["message"],
    }
    assert len(requester.calls) == 1


@pytest.mark.parametrize(
    "data,status",
    [
        ({"ok": True, "result": {}}, 200),
        ({"ok": True, "result": []}, 302),
        ({"ok": False, "description": TOKEN}, 401),
        (RuntimeError(TOKEN), 200),
        ({"ok": True, "result": [private()] * 101}, 200),
    ],
)
def test_setup_failures_fixed_redacted_no_retry(data, status, caplog):
    requester = Requester(data, status)
    with caplog.at_level(logging.DEBUG), pytest.raises(TelegramSetupError) as failure:
        TelegramTransport(TOKEN, requester=requester).get_updates()
    assert TOKEN not in str(failure.value) + caplog.text
    assert len(requester.calls) == 1


def test_default_transport_setup_requests_keep_token_out_of_debug(monkeypatch, caplog):
    class Transport:
        def __init__(self, **kwargs):
            assert kwargs == {"retries": 0, "trust_env": False}

        def handle_request(self, request):
            # Exercise the installed request trace function, including a malicious
            # provider header/exception echo. Compatibility suite covers httpcore.
            info = {
                "exception": RuntimeError(str(request.url)),
                "headers": [(b"echo", TOKEN.encode())],
            }
            request.extensions["trace"]("http11.receive_response_headers.complete", info)
            logging.getLogger("httpcore.http11").debug("%r", info)
            return httpx.Response(
                200, json={"ok": True, "result": {"id": 1, "is_bot": True, "username": "test_bot"}}
            )

        def close(self):
            pass

    monkeypatch.setattr(httpx, "HTTPTransport", Transport)
    with caplog.at_level(logging.DEBUG), TelegramTransport(TOKEN) as transport:
        assert transport.get_me().bot_id == 1
    assert TOKEN not in caplog.text and "A" * 35 not in caplog.text


@pytest.mark.parametrize("method", ["get_me", "get_updates"])
@pytest.mark.parametrize("kind", ["valid", "oversized", "malformed_header"])
def test_actual_httpx_httpcore_setup_stack_is_bounded_and_redacted(method, kind, caplog):
    import httpcore
    from httpcore._backends.mock import MockBackend

    payload = {
        "ok": True,
        "result": {"id": 1, "is_bot": True, "username": "test_bot"}
        if method == "get_me"
        else [private()],
    }
    body = json.dumps(payload).encode()
    if kind == "oversized":
        body = b" " * (256 * 1024 + 1) + body
    headers = "HTTP/1.1 200 OK\r\n"
    headers += ("invalid " if kind == "malformed_header" else "X-Token: ") + TOKEN + "\r\n"
    headers += f"Content-Length: {len(body)}\r\n\r\n"
    backend = MockBackend([headers.encode() + body])
    with caplog.at_level(logging.DEBUG), TelegramTransport(TOKEN) as transport:
        transport._requester._transport._pool.close()
        transport._requester._transport._pool = httpcore.ConnectionPool(network_backend=backend)
        if kind == "valid":
            result = getattr(transport, method)()
            assert result
        else:
            with pytest.raises(TelegramSetupError):
                getattr(transport, method)()
    assert "receive_response_headers" in caplog.text and "<redacted>" in caplog.text
    assert TOKEN not in caplog.text and TOKEN.partition(":")[2] not in caplog.text


@pytest.mark.parametrize(
    "field",
    [
        "forward_date",
        "forward_from_chat",
        "forward_sender_name",
        "is_automatic_forward",
        "sender_chat",
    ],
)
def test_legacy_forwarded_pairing_messages_rejected(field):
    requester = Requester({"ok": True, "result": [private(**{field: "synthetic"})]})
    assert TelegramTransport(TOKEN, requester=requester).get_updates() == ()
