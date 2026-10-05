"""Authenticated loopback inbox, with all persistent work delegated to a facade.

The runtime supplies a bounded, serialized service. This module never creates a
SQLite connection, delivers a notification, or operates a native host request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from urllib.parse import urlsplit

from flask import Flask, abort, g, jsonify, redirect, render_template, request
from markupsafe import Markup
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, ValidationError

from .control import SESSION_TTL, ControlAuth, ControlError
from .presentation.models import (
    DisclosedField,
    PresentationRecord,
    PresentationStatus,
    RequestType,
)
from .presentation.renderers import native_open_target, render_local_html, render_telegram_parts
from .settings import Settings, SettingsConflict, SettingsError, revised_settings, validate_alias
from .view import RecordView

COOKIE_NAME = "decision_mesh_session"
PAGE_SIZE = 50
LOCAL_FIELDS = frozenset(DisclosedField)
FILTERS = ("attention", "confirmed", "unverified", "history")
_REFERENCE = re.compile(r"^[A-HJ-NP-Z2-9]{8}$")


class WebServiceError(RuntimeError):
    """Service failure. Its text is intentionally never reflected to the browser."""


@dataclass(frozen=True)
class InboxCounts:
    attention: int = 0
    confirmed: int = 0
    unverified: int = 0
    history: int = 0
    recent_aged: int = 0

    def __post_init__(self):
        if any(type(v) is not int or v < 0 for v in self.__dict__.values()):
            raise ValueError("invalid_inbox_counts")


@dataclass(frozen=True)
class AliasView:
    identity: str = field(repr=False)
    alias: str
    local_path: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class DiagnosticsView:
    runtime: str = "Runtime evidence unavailable"
    capture: str = "Capture evidence unavailable"
    hook_trust: str = "Hook trust not verified"
    native_support: str = "Native host support not qualified"
    credentials: str = "Credential backend not verified"
    last_capture_at: datetime | None = None


@dataclass(frozen=True)
class DeliveryView:
    occurrence_id: str
    short_references: tuple[str, ...]
    status: str
    attempts: int = 0
    duplicate_possible: bool = False
    retry_available: bool = False


@dataclass(frozen=True)
class InboxSnapshot:
    records: tuple[RecordView, ...]
    counts: InboxCounts
    settings: Settings
    next_cursor: str | None = None
    source_confirmed_supported: bool = False
    diagnostics: DiagnosticsView = field(default_factory=DiagnosticsView)
    aliases: tuple[AliasView, ...] = ()
    deliveries: tuple[DeliveryView, ...] = ()


class InboxService(Protocol):
    """All calls must be bounded. Mutations run on the runtime's single writer.

    snapshot is READ-ONLY: the worker, not a GET request, advances aging. It
    returns authoritative totals over the full retained store, and <=limit
    records selected by filter. Cursors are opaque. recent_aged counts records
    whose original observation aging deadline fell within the previous 24h.
    lookup_reference searches retained records/tombstones regardless of paging.
    rename_alias atomically checks/advances the global settings revision.
    Local views use LOCAL_FIELDS and include_local_details=True; external
    disclosure is separate. LocalDetails never enters Telegram rendering.
    No method is a response/approval or a producer-ingestion operation.
    """

    def snapshot(
        self,
        *,
        now: datetime,
        filter: str = "attention",
        cursor: str | None = None,
        limit: int = PAGE_SIZE,
    ) -> InboxSnapshot: ...

    def lookup_reference(self, reference: str, *, now: datetime) -> RecordView | None: ...
    def mark_seen(self, record_id: str, *, now: datetime) -> None: ...
    def snooze(self, record_id: str, until: datetime, *, now: datetime) -> None: ...
    def set_suppressed(self, record_id: str, suppressed: bool, *, now: datetime) -> None: ...
    def update_settings(
        self, expected_revision: int, changes: dict, *, now: datetime
    ) -> Settings: ...
    def rename_alias(
        self, identity: str, alias: str, expected_revision: int, *, now: datetime
    ) -> None: ...


@dataclass(frozen=True)
class SetupView:
    stage: str = "unavailable"
    message: str = "Telegram setup is unavailable in this runtime."
    recipient: str | None = None
    preview: str | None = None
    preview_id: str | None = None
    pairing_code: str | None = field(default=None, repr=False)
    can_send_test: bool = False


@dataclass(frozen=True)
class SetupCallbacks:
    """Optional setup worker bridge. Only a selected exact preview may be sent.

    status is read-only; callbacks must return redacted SetupView data and enforce
    persisted stage/recipient/preview identity themselves. No token is returned.
    """

    status: Callable[[], SetupView]
    configure_token: Callable[[SecretStr], SetupView] | None = None
    discover: Callable[[], SetupView] | None = None
    pair: Callable[[str], SetupView] | None = None
    send_test: Callable[[str], SetupView] | None = None


@dataclass(frozen=True)
class DeliveryCallbacks:
    include_current: Callable[[tuple[str, ...]], None] | None = None
    manual_retry: Callable[..., None] | None = None
    resume_route: Callable[[], None] | None = None


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class _Challenge(_Input):
    operation: Literal["open", "stop"]
    client_nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class _Control(_Input):
    operation: Literal["open", "stop"]
    challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$")
    instance_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    mac: str = Field(pattern=r"^[0-9a-f]{64}$")


class _Exchange(_Input):
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    reference: str | None = Field(default=None, pattern=r"^[A-HJ-NP-Z2-9]{8}$")


class SettingsChanges(_Input):
    local_layout: Literal["friendly", "compact"] | None = None
    telegram_layout: Literal["friendly", "compact"] | None = None
    delivery_mode: Literal["immediate", "digest"] | None = None
    digest_interval_minutes: StrictInt | None = Field(default=None, ge=1, le=1440)
    global_pause: StrictBool | None = None
    channel_active: StrictBool | None = None
    disclosure_fields: (
        list[Literal["action", "reason", "scope", "chat_title", "source_path", "source_reference"]]
        | None
    ) = None
    device_alias: str | None = Field(default=None, min_length=1, max_length=80)


class _SettingsUpdate(_Input):
    expected_revision: StrictInt = Field(ge=0)
    changes: SettingsChanges
    preview_receipt: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def create_app(
    service: InboxService,
    *,
    origin: str,
    instance_id: str,
    control_secret: bytes,
    clock: Callable[[], datetime] = _utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    request_stop: Callable[[], None] | None = None,
    setup: SetupCallbacks | None = None,
    delivery: DeliveryCallbacks | None = None,
) -> Flask:
    """Create an embeddable app; runtime binds Waitress to this exact origin.

    request_stop queues shutdown and MUST return promptly, allowing the signed
    response to flush before closing the listener. This app never starts a server.
    """
    try:
        parsed = urlsplit(origin)
        valid = (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and 1 <= parsed.port <= 65535
            and origin == f"http://127.0.0.1:{parsed.port}"
        )
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("canonical_loopback_origin_required")
    host = parsed.netloc
    auth = ControlAuth(control_secret, instance_id, monotonic=monotonic, token_bytes=token_bytes)
    app = Flask(__name__, template_folder="ui/templates", static_folder="ui/static")
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,
        MAX_FORM_MEMORY_SIZE=16 * 1024,
        MAX_FORM_PARTS=100,
        PROPAGATE_EXCEPTIONS=False,
    )
    app.extensions["decision_mesh_auth"] = auth
    delivery = delivery or DeliveryCallbacks()

    def now():
        stamp = clock()
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise WebServiceError("invalid_clock")
        return stamp.astimezone(UTC)

    @app.before_request
    def guard():
        if request.host != host or request.remote_addr != "127.0.0.1":
            abort(403)
        supplied_origin = request.headers.get("Origin")
        if supplied_origin is not None and supplied_origin != origin:
            abort(403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)
        if request.method not in ("GET", "HEAD", "POST"):
            abort(405)
        g.session = auth.session(request.cookies.get(COOKIE_NAME))
        if request.path.startswith("/control/"):
            return  # CLI has no Origin; any supplied Origin was checked above.
        if request.method == "POST" and supplied_origin != origin:
            abort(403)
        if request.path == "/auth/exchange" or request.path == "/" or request.endpoint == "static":
            return
        if g.session is None:
            abort(401)
        if request.method == "POST":
            csrf = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
            if (
                not isinstance(csrf, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf)
                or not hmac.compare_digest(g.session.csrf, csrf)
            ):
                abort(403)

    @app.after_request
    def security_headers(response):
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; "
                "frame-ancestors 'none'; object-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                # Keep normal form POST Origins intact; disclose no cross-origin referrer.
                "Referrer-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        return response

    @app.errorhandler(ValidationError)
    @app.errorhandler(SettingsError)
    def invalid_input(_error):
        return render_template("error.html", code=400, message="Invalid request."), 400

    @app.errorhandler(SettingsConflict)
    def conflict(_error):
        return render_template(
            "error.html", code=409, message="Settings changed. Reload before saving again."
        ), 409

    @app.errorhandler(ControlError)
    def auth_error(_error):
        return jsonify(error="authentication_failed"), 403

    @app.errorhandler(WebServiceError)
    def service_error(_error):
        # A callback may have completed before it or the following status read failed.
        return render_template(
            "error.html",
            code=503,
            message="Local service unavailable. The operation outcome could not be confirmed. "
            "Reload its status before retrying; it may have completed.",
        ), 503

    for code in (400, 401, 403, 404, 405, 409, 413, 415, 500):

        def handler(error, code=code):
            return render_template(
                "error.html",
                code=code,
                message="Open the inbox using decision-mesh open."
                if code == 401
                else "Request could not be completed.",
            ), code

        app.register_error_handler(code, handler)

    def call(callback, *args, **kwargs):
        if callback is None:
            raise WebServiceError("operation_unavailable")
        try:
            return callback(*args, **kwargs)
        except (SettingsError, WebServiceError):
            raise
        except Exception:  # noqa: BLE001 - never disclose credential-bearing callback exceptions.
            raise WebServiceError("operation_failed") from None

    def json_input(model):
        if not request.is_json:
            abort(415)
        return model.model_validate(request.get_json())

    def form(allowed):
        if request.mimetype != "application/x-www-form-urlencoded":
            abort(415)
        if set(request.form) - set(allowed) - {"csrf"}:
            abort(400)
        if any(len(request.form.getlist(key)) != 1 for key in request.form if key != "fields"):
            abort(400)
        return request.form

    def integer(value):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,12}", value):
            abort(400)
        return int(value)

    def snapshot(filter="attention", cursor=None):
        result = call(service.snapshot, now=now(), filter=filter, cursor=cursor, limit=PAGE_SIZE)
        if not isinstance(result, InboxSnapshot) or len(result.records) > PAGE_SIZE:
            raise WebServiceError("invalid_snapshot")
        return result

    def find(reference):
        if not _REFERENCE.fullmatch(reference):
            abort(404)
        record = call(service.lookup_reference, reference, now=now())
        if record is None:
            abort(404)
        return record

    @app.get("/")
    def index():
        return render_template("bootstrap.html")

    @app.post("/control/challenge")
    def control_challenge():
        data = json_input(_Challenge)
        if data.operation == "stop" and request_stop is None:
            abort(404)
        return jsonify(
            challenge=auth.challenge(data.operation, data.client_nonce), instance_id=instance_id
        )

    @app.post("/control/<operation>")
    def control_request(operation):
        if operation not in ("open", "stop") or (operation == "stop" and request_stop is None):
            abort(404)
        data = json_input(_Control)
        if operation != data.operation:
            abort(400)
        reply = auth.authorize(data.operation, data.challenge, data.instance_id, data.mac)
        response = jsonify(reply.to_dict())
        if operation == "stop":
            # The runtime callback queues a bounded grace period; no listener close here.
            call(request_stop)
        return response

    @app.post("/auth/exchange")
    def exchange():
        data = json_input(_Exchange)
        token, _session = auth.exchange(data.nonce)
        response = jsonify(location=f"/records/{data.reference}" if data.reference else "/inbox")
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=SESSION_TTL,
            httponly=True,
            samesite="Strict",
            secure=False,
            path="/",
        )
        return response

    @app.post("/auth/signout")
    def signout():
        form(())
        auth.sign_out()
        response = redirect("/", code=303)
        response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="Strict")
        return response

    @app.get("/inbox")
    def inbox():
        reference = request.args.get("short_reference")
        if reference is not None:
            reference = reference.strip().upper()
            find(reference)  # ALL history, not the current filter/page.
            return redirect(f"/records/{reference}", code=303)
        selected = request.args.get("filter", "attention")
        if selected not in FILTERS:
            abort(400)
        cursor = request.args.get("cursor")
        if cursor is not None and len(cursor) > 512:
            abort(400)
        state = snapshot(selected, cursor)
        return render_template(
            "inbox.html",
            state=state,
            selected=selected,
            layout=state.settings.local_layout.value,
            fields=LOCAL_FIELDS,
            native_target=native_open_target,
        )

    @app.get("/records/<reference>")
    def detail(reference):
        record = find(reference)
        state = snapshot()
        rendered = (
            render_local_html(
                (record.presentation,),
                layout=state.settings.local_layout.value,
                allowed_fields=LOCAL_FIELDS,
            )
            if record.presentation
            else None
        )
        return render_template(
            "detail.html",
            record=record,
            state=state,
            rendered=Markup(rendered) if rendered else None,
            now=now(),
            include_current_available=delivery.include_current is not None,
        )

    @app.post("/records/<reference>/seen")
    def seen(reference):
        form(())
        call(service.mark_seen, find(reference).record_id, now=now())
        return redirect(f"/records/{reference}", code=303)

    @app.post("/records/<reference>/snooze")
    def snooze(reference):
        values = form(("duration", "until"))
        stamp = now()
        duration = values.get("duration")
        if duration in ("10", "60"):
            until = stamp + timedelta(minutes=int(duration))
        elif duration == "custom":
            try:
                until = datetime.fromisoformat(values.get("until", ""))
            except ValueError:
                abort(400)
            if until.tzinfo is None or until.utcoffset() is None:
                abort(400)
            until = until.astimezone(UTC)
        else:
            abort(400)
        if until <= stamp:
            abort(400)
        call(service.snooze, find(reference).record_id, until, now=stamp)
        return redirect(f"/records/{reference}", code=303)

    @app.post("/records/<reference>/suppress")
    def suppress(reference):
        values = form(("suppressed",))
        if values.get("suppressed") not in ("true", "false"):
            abort(400)
        call(
            service.set_suppressed,
            find(reference).record_id,
            values["suppressed"] == "true",
            now=now(),
        )
        return redirect(f"/records/{reference}", code=303)

    def setup_view():
        return call(setup.status) if setup else SetupView()

    def settings_page(setup_state=None):
        state = snapshot()
        previews = []
        # Real data preview is owner-only, escaped plain text, and exact for chosen fields.
        for record in state.records[:3]:
            if record.presentation:
                previews.extend(
                    part.text
                    for part in render_telegram_parts(
                        (record.presentation,),
                        layout=state.settings.telegram_layout.value,
                        allowed_fields=state.settings.disclosure_fields,
                    )
                )
        return render_template(
            "settings.html",
            state=state,
            previews=previews,
            setup=setup_state or setup_view(),
            setup_callbacks=setup,
            delivery_callbacks=delivery,
        )

    @app.get("/settings")
    def settings_get():
        return settings_page()

    def settings_input():
        if request.is_json:
            data = json_input(_SettingsUpdate)
        else:
            values = form(
                (
                    "expected_revision",
                    "local_layout",
                    "telegram_layout",
                    "delivery_mode",
                    "digest_interval_minutes",
                    "global_pause",
                    "channel_active",
                    "device_alias",
                    "fields",
                    "changes",
                    "preview_receipt",
                )
            )
            if "changes" in values:
                try:
                    changes = json.loads(values["changes"])
                except ValueError:
                    abort(400)
                return _SettingsUpdate(
                    expected_revision=integer(values.get("expected_revision")),
                    changes=SettingsChanges.model_validate(changes),
                    preview_receipt=values.get("preview_receipt"),
                )
            changes = {
                key: values[key]
                for key in ("local_layout", "telegram_layout", "delivery_mode", "device_alias")
                if key in values
            }
            changes.update(
                digest_interval_minutes=integer(values.get("digest_interval_minutes")),
                global_pause=values.get("global_pause") == "on",
                channel_active=values.get("channel_active") == "on",
                disclosure_fields=values.getlist("fields"),
            )
            data = _SettingsUpdate(
                expected_revision=integer(values.get("expected_revision")),
                changes=SettingsChanges.model_validate(changes),
            )
        return data

    def validated_changes(data):
        changes = data.changes.model_dump(exclude_unset=True)
        if any(value is None for value in changes.values()):
            abort(400)
        if "device_alias" in changes:
            validate_alias(changes["device_alias"])
        return changes

    def preview_receipt(data):
        body = json.dumps(
            [
                "decision-mesh/privacy-preview/v1",
                g.session.csrf,
                data.expected_revision,
                validated_changes(data),
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(control_secret, body, hashlib.sha256).hexdigest()

    @app.post("/settings/preview")
    def settings_preview():
        data = settings_input()
        changes = validated_changes(data)
        state = snapshot()
        if data.expected_revision != state.settings.revision:
            raise SettingsConflict("stale_revision")
        candidate = revised_settings(state.settings, changes)
        sample = PresentationRecord(
            record_id="synthetic-preview",
            short_reference="ABCDEFGH",
            request_type=RequestType.QUESTION,
            status=PresentationStatus.AGENT_REPORTED_QUESTION,
            captured_at=now(),
            age_seconds=0,
            device_alias=candidate.device_alias,
            action="Example task description",
            reason="Example reason",
            scope="Example requested scope",
            chat_title="Example chat title",
            source_path="C:/Example/Project",
            source_reference="example-chat-reference",
        )
        previews = [
            part.text
            for part in render_telegram_parts(
                (sample,),
                layout=candidate.telegram_layout.value,
                allowed_fields=candidate.disclosure_fields,
            )
        ]
        receipt = preview_receipt(data)
        if request.is_json:
            return jsonify(
                previews=previews, preview_receipt=receipt, expected_revision=data.expected_revision
            )
        return render_template(
            "preview.html",
            previews=previews,
            data=data,
            changes_json=json.dumps(changes),
            receipt=receipt,
        )

    @app.post("/settings")
    def settings_post():
        data = settings_input()
        changes = validated_changes(data)
        current = snapshot().settings
        if data.expected_revision != current.revision:
            raise SettingsConflict("stale_revision")
        grant = changes.get("disclosure_fields", [])
        if set(grant) - set(current.disclosure_fields) and (
            not data.preview_receipt
            or not hmac.compare_digest(preview_receipt(data), data.preview_receipt)
        ):
            abort(409)
        call(service.update_settings, data.expected_revision, changes, now=now())
        return redirect("/settings", code=303)

    @app.post("/settings/alias")
    def alias():
        values = form(("identity", "alias", "expected_revision"))
        identity = values.get("identity", "")
        if not identity or len(identity) > 2048:
            abort(400)
        alias = validate_alias(values.get("alias", ""))
        call(
            service.rename_alias,
            identity,
            alias,
            integer(values.get("expected_revision")),
            now=now(),
        )
        return redirect("/settings", code=303)

    @app.post("/setup/token")
    def setup_token():
        values = form(("token",))
        token = values.get("token", "")
        if not token or len(token) > 256:
            abort(400)
        result = call(setup.configure_token if setup else None, SecretStr(token))
        return settings_page(result)

    @app.post("/setup/discover")
    def setup_discover():
        form(())
        return settings_page(call(setup.discover if setup else None))

    @app.post("/setup/pair")
    def setup_pair():
        values = form(("code",))
        code = values.get("code", "")
        if not code or len(code) > 128:
            abort(400)
        return settings_page(call(setup.pair if setup else None, code))

    @app.post("/setup/send-test")
    def setup_send_test():
        values = form(("preview_id",))
        current = setup_view()
        preview_id = values.get("preview_id", "")
        if (
            not current.can_send_test
            or not current.preview_id
            or not preview_id
            or not hmac.compare_digest(
                preview_id.encode("utf-8"), current.preview_id.encode("utf-8")
            )
        ):
            abort(409)
        return settings_page(call(setup.send_test if setup else None, preview_id))

    @app.post("/delivery/<occurrence_id>/retry")
    def delivery_retry(occurrence_id):
        values = form(("acknowledge_duplicate",))
        if len(occurrence_id) > 256:
            abort(400)
        call(
            delivery.manual_retry,
            occurrence_id,
            acknowledge_duplicate=values.get("acknowledge_duplicate") == "on",
        )
        return redirect("/settings", code=303)

    @app.post("/delivery/resume-notifications")
    def resume_notifications():
        form(())
        call(delivery.resume_route)
        return redirect("/settings", code=303)

    @app.post("/records/<reference>/include-current")
    def include_current(reference):
        values = form(("confirm",))
        if values.get("confirm") != "on":
            abort(400)
        call(delivery.include_current, (find(reference).record_id,))
        return redirect(f"/records/{reference}", code=303)

    @app.context_processor
    def common():
        return {
            "csrf": g.session.csrf if getattr(g, "session", None) else "",
            "authenticated": bool(getattr(g, "session", None)),
            "timedelta": timedelta,
            "PresentationStatus": PresentationStatus,
        }

    return app
