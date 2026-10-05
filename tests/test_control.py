"""Synthetic local authentication tests; no native process/browser qualification."""

import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor

import pytest

from decision_mesh.control import (
    ControlAuth,
    ControlError,
    new_client_nonce,
    request_mac,
    response_mac,
    verify_challenge,
    verify_response,
)

SECRET = bytes(range(32))
INSTANCE = "instance-one"


class MonoClock:
    value = 100.0

    def __call__(self):
        return self.value


def opened(auth):
    challenge = auth.challenge("open")
    return auth.authorize(
        "open", challenge, INSTANCE, request_mac(SECRET, "open", challenge, INSTANCE)
    )


def test_wire_encoding_independent_vector_and_domains():
    challenge = "A" * 43 + "." + "B" * 43
    request_body = (
        '["decision-mesh/control/request/v1","open","' + challenge + '","instance-one"]'
    ).encode()
    expected = hmac.new(SECRET, request_body, hashlib.sha256).hexdigest()
    assert request_mac(SECRET, "open", challenge, INSTANCE) == expected
    assert response_mac(SECRET, "open", challenge, INSTANCE, "B" * 43, "ok") != expected
    assert request_mac(SECRET, "stop", challenge, INSTANCE) != expected


def test_authenticated_reply_and_secret_not_in_repr():
    auth = ControlAuth(SECRET, INSTANCE)
    reply = opened(auth)
    assert (
        verify_response(
            SECRET,
            reply.to_dict(),
            operation="open",
            challenge=reply.challenge,
            instance_id=INSTANCE,
        )
        == reply
    )
    assert reply.nonce not in repr(reply)
    assert reply.mac not in repr(reply)
    token, session = auth.exchange(reply.nonce)
    assert session.csrf not in repr(session)
    assert auth.session(token) == session
    assert SECRET.hex() not in repr(auth)


@pytest.mark.parametrize(
    "field,value",
    [
        ("instance_id", "stale-instance"),
        ("operation", "stop"),
        ("challenge", "B" * 43),
        ("nonce", "C" * 43),
        ("result", "stopping"),
        ("mac", "0" * 64),
        ("nonce", None),
    ],
)
def test_client_rejects_stale_listener_or_tampered_response(field, value):
    reply = opened(ControlAuth(SECRET, INSTANCE))
    with pytest.raises(ControlError):
        verify_response(
            SECRET,
            reply.to_dict() | {field: value},
            operation="open",
            challenge=reply.challenge,
            instance_id=INSTANCE,
        )


def test_response_rejects_wrong_key_and_extra_fields():
    reply = opened(ControlAuth(SECRET, INSTANCE))
    for secret, payload in [
        (b"z" * 32, reply.to_dict()),
        (SECRET, reply.to_dict() | {"token": "bad"}),
    ]:
        with pytest.raises(ControlError):
            verify_response(
                secret, payload, operation="open", challenge=reply.challenge, instance_id=INSTANCE
            )


def test_expired_challenge_nonce_and_twelve_hour_session():
    clock = MonoClock()
    auth = ControlAuth(SECRET, INSTANCE, monotonic=clock)
    challenge = auth.challenge("open")
    clock.value += 60
    with pytest.raises(ControlError):
        auth.authorize(
            "open", challenge, INSTANCE, request_mac(SECRET, "open", challenge, INSTANCE)
        )
    reply = opened(auth)
    clock.value += 60
    with pytest.raises(ControlError):
        auth.exchange(reply.nonce)
    token, session = auth.exchange(opened(auth).nonce)
    clock.value += 43199
    assert auth.session(token) == session
    clock.value += 1
    assert auth.session(token) is None


def test_challenge_and_nonce_cannot_be_replayed():
    auth = ControlAuth(SECRET, INSTANCE)
    reply = opened(auth)
    with pytest.raises(ControlError):
        auth.authorize(
            "open",
            reply.challenge,
            INSTANCE,
            request_mac(SECRET, "open", reply.challenge, INSTANCE),
        )
    auth.exchange(reply.nonce)
    with pytest.raises(ControlError):
        auth.exchange(reply.nonce)


def test_challenge_binds_operation_and_instance():
    auth = ControlAuth(SECRET, INSTANCE)
    challenge = auth.challenge("open")
    for operation, instance in [("stop", INSTANCE), ("open", "other")]:
        with pytest.raises(ControlError):
            auth.authorize(
                operation, challenge, instance, request_mac(SECRET, operation, challenge, instance)
            )


def test_stop_reply_has_no_browser_nonce_and_binds_result():
    auth = ControlAuth(SECRET, INSTANCE)
    challenge = auth.challenge("stop")
    reply = auth.authorize(
        "stop", challenge, INSTANCE, request_mac(SECRET, "stop", challenge, INSTANCE)
    )
    assert reply.nonce == "" and reply.result == "stopping"
    assert (
        verify_response(
            SECRET, reply.to_dict(), operation="stop", challenge=challenge, instance_id=INSTANCE
        ).result
        == "stopping"
    )


def test_signout_revokes_all_sessions_and_pending_auth():
    auth = ControlAuth(SECRET, INSTANCE)
    tokens = [auth.exchange(opened(auth).nonce)[0] for _ in range(2)]
    reply = opened(auth)
    challenge = auth.challenge("open")
    auth.sign_out()
    assert all(auth.session(token) is None for token in tokens)
    with pytest.raises(ControlError):
        auth.exchange(reply.nonce)
    with pytest.raises(ControlError):
        auth.authorize(
            "open", challenge, INSTANCE, request_mac(SECRET, "open", challenge, INSTANCE)
        )


def test_restart_revokes_sessions_and_old_instance_request():
    old = ControlAuth(SECRET, INSTANCE)
    token = old.exchange(opened(old).nonce)[0]
    new = ControlAuth(b"n" * 32, "instance-two")
    assert new.session(token) is None
    challenge = new.challenge("open")
    with pytest.raises(ControlError):
        new.authorize("open", challenge, INSTANCE, request_mac(SECRET, "open", challenge, INSTANCE))


def test_concurrent_exchange_only_one_wins():
    auth = ControlAuth(SECRET, INSTANCE)
    nonce = opened(auth).nonce

    def attempt(_):
        try:
            auth.exchange(nonce)
            return True
        except ControlError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(16))) == 1


def test_authentication_cache_bounded_and_recovers_after_expiry():
    clock = MonoClock()
    auth = ControlAuth(SECRET, INSTANCE, monotonic=clock, capacity=1)
    auth.challenge("open")
    with pytest.raises(ControlError):
        auth.challenge("open")
    clock.value += 60
    auth.challenge("open")


def test_fresh_client_challenge_defeats_stale_listener_replay():
    auth = ControlAuth(SECRET, INSTANCE)
    client_nonce = new_client_nonce()
    challenge = auth.challenge("open", client_nonce)
    response = {"challenge": challenge, "instance_id": INSTANCE}
    assert verify_challenge(response, client_nonce=client_nonce, instance_id=INSTANCE) == challenge
    with pytest.raises(ControlError):
        verify_challenge(response, client_nonce=new_client_nonce(), instance_id=INSTANCE)
    # Repeating a client nonce still gets fresh server entropy, never the old signature input.
    assert auth.challenge("open", client_nonce) != challenge


@pytest.mark.parametrize("secret,instance", [(b"short", INSTANCE), (SECRET, "bad\ninstance")])
def test_invalid_configuration_rejected(secret, instance):
    with pytest.raises(ControlError):
        ControlAuth(secret, instance)


@pytest.mark.parametrize("operation", ["approve", "resume", "producer", "__dict__"])
def test_no_arbitrary_control_dispatch(operation):
    with pytest.raises(ControlError):
        ControlAuth(SECRET, INSTANCE).challenge(operation)
