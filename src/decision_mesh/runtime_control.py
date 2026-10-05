"""Owned process rendezvous and bounded, authenticated loopback control."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sysconfig
import threading
import time
import uuid
from dataclasses import dataclass
from http.cookies import SimpleCookie
from importlib import metadata
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .capture import (
    CaptureError,
    assert_owner_only,
    atomic_write_owner_only,
    ensure_spool_dir,
    owner_file_lock,
    parse_json,
)
from .control import new_client_nonce, request_mac, verify_challenge, verify_response

CONTROL_TIMEOUT = 1.0
READINESS_TIMEOUT = 10.0
LOCAL_SETUP_TIMEOUT = 10.0
METADATA_LIMIT = 4096
REFERENCE = re.compile(r"^[A-HJ-NP-Z2-9]{8}$")


class RuntimeErrorCode(RuntimeError):
    """Fixed error codes only; no input, path, secret or HTTP body."""


@dataclass(frozen=True)
class RuntimePaths:
    root: Path

    def __post_init__(self):
        root = Path(self.root)
        if not root.is_absolute():
            raise RuntimeErrorCode("absolute_data_directory_required")
        object.__setattr__(self, "root", root)

    @property
    def lock(self):
        return self.root / "runtime.lock"

    @property
    def metadata(self):
        return self.root / "runtime.json"

    @property
    def database(self):
        return self.root / "decisionmesh.db"

    @property
    def producer(self):
        return self.root / "producer"

    @property
    def policy(self):
        return self.root / "capture-policy.json"


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "DecisionMesh"


class RuntimeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    schema_version: Literal[1] = 1
    instance_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    port: Annotated[StrictInt, Field(ge=1, le=65535)]
    control_secret: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    @property
    def secret(self):
        return bytes.fromhex(self.control_secret)


def read_metadata(paths: RuntimePaths) -> RuntimeMetadata:
    try:
        assert_owner_only(paths.root)
        assert_owner_only(paths.metadata)
        with paths.metadata.open("rb") as stream:
            raw = stream.read(METADATA_LIMIT + 1)
        return RuntimeMetadata.model_validate(parse_json(raw, METADATA_LIMIT))
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        raise RuntimeErrorCode("runtime_metadata_unavailable") from None


def publish_metadata(
    paths: RuntimePaths, port: int, secret: bytes, *, instance_id: str | None = None
) -> RuntimeMetadata:
    if len(secret) != 32:
        raise RuntimeErrorCode("invalid_control_secret")
    metadata = RuntimeMetadata(
        instance_id=instance_id or uuid.uuid4().hex, port=port, control_secret=secret.hex()
    )
    atomic_write_owner_only(
        paths.metadata, metadata.model_dump_json().encode(), max_bytes=METADATA_LIMIT
    )
    return metadata


def remove_metadata(paths: RuntimePaths) -> None:
    # Caller holds the lifetime lock, or is its runtime owner before releasing it.
    if paths.metadata.exists() or paths.metadata.is_symlink():
        assert_owner_only(paths.metadata)
        paths.metadata.unlink()


def active_metadata(paths: RuntimePaths) -> RuntimeMetadata | None:
    """A free lifetime lock means stale metadata; never contact its old port."""
    if not paths.root.exists():
        return None
    assert_owner_only(paths.root)
    try:
        with owner_file_lock(paths.lock, timeout=0):
            remove_metadata(paths)
            return None
    except CaptureError as exc:
        if exc.code != "capture_busy":
            raise RuntimeErrorCode("runtime_lock_unavailable") from None
    if not paths.metadata.exists():
        raise RuntimeErrorCode("runtime_starting")
    return read_metadata(paths)


def _post(
    port: int,
    path: str,
    payload: dict | None,
    *,
    timeout: float,
    method="POST",
    headers=None,
    response_headers=None,
) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    timer = None
    started = time.monotonic()

    def abort():
        if connection.sock:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    try:
        connection.connect()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise RuntimeErrorCode("runtime_authentication_failed")
        timer = threading.Timer(remaining, abort)
        timer.daemon = True
        timer.start()
        # http.client does not use environment proxies or follow redirects.
        body = (
            None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        connection.request(
            method, path, body, {"Content-Type": "application/json"} | (headers or {})
        )
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Type", "").split(";")[0] != "application/json"
        ):
            raise RuntimeErrorCode("runtime_authentication_failed")
        raw = response.read(METADATA_LIMIT + 1)
        if response_headers is not None:
            response_headers["Set-Cookie"] = response.getheader("Set-Cookie", "")
        return parse_json(raw, METADATA_LIMIT)
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        raise RuntimeErrorCode("runtime_authentication_failed") from None
    finally:
        if timer:
            timer.cancel()
        connection.close()


def authenticate(metadata: RuntimeMetadata, operation: str, *, deadline: float | None = None):
    if operation not in {"open", "stop"}:
        raise RuntimeErrorCode("invalid_control_operation")

    def timeout():
        left = (
            CONTROL_TIMEOUT
            if deadline is None
            else min(CONTROL_TIMEOUT, deadline - time.monotonic())
        )
        if left <= 0:
            raise RuntimeErrorCode("runtime_readiness_timeout")
        return left

    try:
        nonce = new_client_nonce()
        response = _post(
            metadata.port,
            "/control/challenge",
            {"operation": operation, "client_nonce": nonce},
            timeout=timeout(),
        )
        challenge = verify_challenge(response, client_nonce=nonce, instance_id=metadata.instance_id)
        response = _post(
            metadata.port,
            "/control/" + operation,
            {
                "operation": operation,
                "challenge": challenge,
                "instance_id": metadata.instance_id,
                "mac": request_mac(metadata.secret, operation, challenge, metadata.instance_id),
            },
            timeout=timeout(),
        )
        return verify_response(
            metadata.secret,
            response,
            operation=operation,
            challenge=challenge,
            instance_id=metadata.instance_id,
        )
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        raise RuntimeErrorCode("runtime_authentication_failed") from None


def resolve_installed_console() -> Path:
    """Resolve only this interpreter's verified installed distribution launcher."""
    try:
        distribution = metadata.distribution("decision-mesh")
        module = Path(__file__).resolve(strict=True)
        if Path(distribution.locate_file("decision_mesh/runtime_control.py")).resolve(
            strict=True
        ) != module or not module.is_relative_to(
            Path(sysconfig.get_path("purelib")).resolve(strict=True)
        ):
            raise ValueError()
        if not any(
            entry.group == "console_scripts"
            and entry.name == "decisionmesh"
            and entry.value == "decision_mesh.cli:main"
            for entry in distribution.entry_points
        ):
            raise ValueError()
        executable = Path(sysconfig.get_path("scripts")) / (
            "decisionmesh.exe" if os.name == "nt" else "decisionmesh"
        )
        if executable.is_symlink() or not executable.is_file():
            raise ValueError()
        executable = executable.resolve(strict=True)
        entries = [
            entry
            for entry in distribution.files or ()
            if Path(distribution.locate_file(entry)).resolve() == executable
        ]
        if len(entries) != 1 or entries[0].hash is None or entries[0].hash.mode != "sha256":
            raise ValueError()
        with executable.open("rb") as stream:
            body = stream.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024 or len(body) != entries[0].size:
            raise ValueError()
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode("ascii")
        )
        if digest != entries[0].hash.value:
            raise ValueError()
        return executable
    except Exception:  # noqa: BLE001 - no paths or package metadata in CLI errors
        raise RuntimeErrorCode("installed_command_unavailable") from None


def launch_hidden(paths: RuntimePaths, *, local_only=False):
    executable = resolve_installed_console()
    args = [str(executable), "run", "--data-dir", str(paths.root)]
    if local_only:
        args.append("--local-only")
    options = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        options.update(startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        options["start_new_session"] = True
    return subprocess.Popen(args, **options)


def _ready(paths, *, launcher=launch_hidden, local_only=False):
    deadline = time.monotonic() + READINESS_TIMEOUT
    starting = False
    try:
        metadata = active_metadata(paths)
    except RuntimeErrorCode as exc:
        if str(exc) != "runtime_starting":
            raise
        metadata, starting = None, True
    if metadata is None:
        if not starting:
            ensure_spool_dir(paths.root)
            launcher(paths, local_only=local_only)
        while time.monotonic() < deadline:
            try:
                metadata = active_metadata(paths)
                if metadata is not None:
                    reply = authenticate(metadata, "open", deadline=deadline)
                    break
            except RuntimeErrorCode:
                pass
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        else:
            raise RuntimeErrorCode("runtime_readiness_timeout")
    else:
        reply = authenticate(metadata, "open", deadline=deadline)
    return metadata, reply


def setup_action(paths, *, action, local_only=False):
    """Use the existing HMAC bootstrap and authenticated CSRF session, no browser."""
    if action not in {"verification", "reconcile"}:
        raise RuntimeErrorCode("invalid_setup_action")
    metadata, reply = _ready(paths, local_only=local_only)
    cookie_headers = {}
    _post(
        metadata.port,
        "/auth/exchange",
        {"nonce": reply.nonce, "reference": None},
        timeout=CONTROL_TIMEOUT,
        headers={"Origin": metadata.origin},
        response_headers=cookie_headers,
    )
    try:
        cookies = SimpleCookie(cookie_headers["Set-Cookie"])
        cookie = cookies["decision_mesh_session"].value
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie):
            raise ValueError()
        headers = {"Origin": metadata.origin, "Cookie": "decision_mesh_session=" + cookie}
        session = _post(
            metadata.port,
            "/runtime/setup/verification",
            None,
            method="GET",
            timeout=CONTROL_TIMEOUT,
            headers=headers,
        )
        csrf = session["csrf"]
        if not isinstance(csrf, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf):
            raise ValueError()
        result = _post(
            metadata.port,
            "/runtime/setup/" + action,
            {},
            timeout=LOCAL_SETUP_TIMEOUT,
            headers=headers | {"X-CSRF-Token": csrf},
        )
        if type(result.get("ok")) is not bool:
            raise ValueError()
        if action == "verification":
            expected = {
                "ok",
                "scope",
                "environment_verified",
                "local_capture_verified",
                "native_qualification",
                "hook_trust",
                "policy_ready",
                "reconciliation_required",
                "status",
            }
            if (
                set(result) != expected
                or result["scope"] != "local_runtime"
                or result["native_qualification"] != "unverified"
                or result["hook_trust"] != "unverified"
                or any(
                    type(result[key]) is not bool
                    for key in (
                        "environment_verified",
                        "local_capture_verified",
                        "policy_ready",
                        "reconciliation_required",
                    )
                )
                or result["status"]
                not in {"local_verification_complete", "local_verification_incomplete"}
            ):
                raise ValueError()
        elif set(result) != {"ok", "status"} or result["status"] not in {
            "configuration_ready",
            "configuration_incomplete",
        }:
            raise ValueError()
        return result
    except Exception:  # noqa: BLE001 - authentication/session fields never appear in errors
        raise RuntimeErrorCode("local_setup_outcome_unconfirmed") from None


def open_inbox(paths, *, reference=None, browser=None, launcher=launch_hidden, local_only=False):
    if reference is not None and not REFERENCE.fullmatch(reference):
        raise RuntimeErrorCode("invalid_short_reference")
    metadata, reply = _ready(paths, launcher=launcher, local_only=local_only)
    if browser is None:
        import webbrowser

        browser = webbrowser.open
    target = metadata.origin + "/#nonce=" + reply.nonce
    if reference:
        target += "&reference=" + reference
    if not browser(target):
        raise RuntimeErrorCode("browser_open_failed")


def stop_runtime(paths: RuntimePaths) -> bool:
    metadata = active_metadata(paths)
    if metadata is None:
        return False
    authenticate(metadata, "stop")
    return True
