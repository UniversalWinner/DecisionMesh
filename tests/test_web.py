"""Flask-client interface/security fixtures; real browser qualification is separate."""

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from uuid import UUID

import pytest

from decision_mesh.control import new_client_nonce, request_mac, verify_challenge, verify_response
from decision_mesh.presentation.models import (
    NativeChatReference,
    PresentationRecord,
    PresentationStatus,
    RequestType,
)
from decision_mesh.settings import Settings, SettingsConflict, revised_settings
from decision_mesh.view import LocalDetails, RecordView, record_view
from decision_mesh.web import (
    COOKIE_NAME,
    LOCAL_FIELDS,
    AliasView,
    DeliveryCallbacks,
    DeliveryView,
    InboxCounts,
    InboxSnapshot,
    SetupCallbacks,
    SetupView,
    create_app,
)

NOW = datetime(2026, 10, 4, 10, tzinfo=UTC)
ORIGIN = "http://127.0.0.1:43217"
INSTANCE = "test-instance"
SECRET = b"T" * 32


def view(reference="ABCDEFGH", status=PresentationStatus.AGENT_REPORTED_QUESTION, **changes):
    confirmed = status == PresentationStatus.CURRENT_CONFIRMED_PENDING
    last_known = status == PresentationStatus.LAST_KNOWN_PENDING
    historical = status in {PresentationStatus.OBSERVATION_AGED, PresentationStatus.ANSWERED}
    stamp = NOW - timedelta(hours=2) if historical else NOW - timedelta(minutes=5)
    presentation = PresentationRecord(
        record_id=f"record-{reference}",
        short_reference=reference,
        request_type=RequestType.QUESTION,
        status=status,
        captured_at=stamp,
        age_seconds=int((NOW - stamp).total_seconds()),
        last_confirmed_at=stamp if confirmed or last_known else None,
        action="Select an option",
        reason="A question needs context",
        scope="This task",
    )
    result = RecordView(
        record_id=presentation.record_id,
        short_reference=reference,
        presentation=presentation,
        status=status,
        evidence_label=presentation.evidence_label,
        captured_at=stamp,
        aging_deadline=None if confirmed or last_known else stamp + timedelta(hours=1),
        age_seconds=presentation.age_seconds,
        last_confirmed_at=presentation.last_confirmed_at,
        source_state="pending" if confirmed or last_known else "unverified",
        evidence_class="producer_reported",
        execution_state="not_observed",
        connection_state="continuous" if confirmed else "unknown",
        seen=False,
        snoozed_until=None,
        suppressed=False,
        history=historical,
        detail_available=True,
        detail_label="Details available",
        needs_attention=confirmed
        or status
        in {PresentationStatus.AGENT_REPORTED_QUESTION, PresentationStatus.PROMPT_OBSERVED},
        source_confirmed_pending=confirmed,
        status_unverified=last_known or status == PresentationStatus.GATE_OBSERVED,
        delivery_state=None,
    )
    return replace(result, **changes)


class FakeService:
    def __init__(self, records=None):
        self.records = {r.short_reference: r for r in (records or [view()])}
        self.settings = Settings()
        self.supported = False
        self.calls = []
        self.aliases = (AliasView("identity-one", "Project 1", "C:/Local/Example"),)
        self.deliveries = ()

    def snapshot(self, *, now, filter="attention", cursor=None, limit=50):
        self.calls.append(("snapshot", filter, cursor, limit))
        all_rows = list(self.records.values())
        attrs = {
            "attention": "needs_attention",
            "confirmed": "source_confirmed_pending",
            "unverified": "status_unverified",
            "history": "history",
        }
        counts = {key: sum(bool(getattr(r, attr)) for r in all_rows) for key, attr in attrs.items()}
        counts["recent_aged"] = sum(
            r.status == PresentationStatus.OBSERVATION_AGED
            and r.aging_deadline
            and now - timedelta(hours=24) <= r.aging_deadline <= now
            for r in all_rows
        )
        rows = [r for r in all_rows if getattr(r, attrs[filter])]
        start = int(cursor or 0)
        return InboxSnapshot(
            records=tuple(rows[start : start + limit]),
            counts=InboxCounts(**counts),
            settings=self.settings,
            next_cursor=str(start + limit) if len(rows) > start + limit else None,
            source_confirmed_supported=self.supported,
            aliases=self.aliases,
            deliveries=self.deliveries,
        )

    def lookup_reference(self, reference, *, now):
        self.calls.append(("lookup", reference))
        return self.records.get(reference)

    def _replace(self, record_id, **changes):
        ref = next(r.short_reference for r in self.records.values() if r.record_id == record_id)
        self.records[ref] = replace(self.records[ref], **changes)

    def mark_seen(self, record_id, *, now):
        self.calls.append(("seen", record_id, now))
        row = next(r for r in self.records.values() if r.record_id == record_id)
        self._replace(record_id, seen=True, needs_attention=row.source_confirmed_pending)

    def snooze(self, record_id, until, *, now):
        self.calls.append(("snooze", record_id, until, now))
        self._replace(record_id, snoozed_until=until, needs_attention=False)

    def set_suppressed(self, record_id, suppressed, *, now):
        self.calls.append(("suppress", record_id, suppressed, now))
        self._replace(record_id, suppressed=suppressed)

    def update_settings(self, expected_revision, changes, *, now):
        if expected_revision != self.settings.revision:
            raise SettingsConflict("stale_settings_revision")
        self.settings = revised_settings(self.settings, changes)
        self.calls.append(("settings", expected_revision, changes))
        return self.settings

    def rename_alias(self, identity, alias, expected_revision, *, now):
        if expected_revision != self.settings.revision:
            raise SettingsConflict("stale_settings_revision")
        self.settings = revised_settings(self.settings, {})
        self.aliases = (AliasView(identity, alias, self.aliases[0].local_path),)
        self.calls.append(("alias", identity, alias, expected_revision))


class Harness:
    def __init__(self, service=None, **kwargs):
        self.service = service or FakeService()
        self.mono = 100.0
        self.app = create_app(
            self.service,
            origin=ORIGIN,
            instance_id=INSTANCE,
            control_secret=SECRET,
            clock=lambda: NOW,
            monotonic=lambda: self.mono,
            **kwargs,
        )
        self.client = self.app.test_client()
        self.csrf = None

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=ORIGIN, **kwargs)

    def post(self, path, data=None, json=None, **kwargs):
        headers = {"Origin": ORIGIN} | kwargs.pop("headers", {})
        if self.csrf:
            headers.setdefault("X-CSRF-Token", self.csrf)
        if data is not None:
            kwargs.setdefault("content_type", "application/x-www-form-urlencoded")
        return self.client.post(
            path, base_url=ORIGIN, data=data, json=json, headers=headers, **kwargs
        )

    def nonce(self, operation="open"):
        client_nonce = new_client_nonce()
        result = self.post(
            "/control/challenge", json={"operation": operation, "client_nonce": client_nonce}
        ).get_json()
        challenge = verify_challenge(result, client_nonce=client_nonce, instance_id=INSTANCE)
        payload = {
            "operation": operation,
            "challenge": challenge,
            "instance_id": INSTANCE,
            "mac": request_mac(SECRET, operation, challenge, INSTANCE),
        }
        response = self.post(f"/control/{operation}", json=payload)
        assert response.status_code == 200
        return verify_response(
            SECRET,
            response.get_json(),
            operation=operation,
            challenge=result["challenge"],
            instance_id=INSTANCE,
        )

    def login(self, reference=None):
        response = self.post(
            "/auth/exchange", json={"nonce": self.nonce().nonce, "reference": reference}
        )
        assert response.status_code == 200
        html = self.get("/inbox").text
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]
        return response


@pytest.fixture
def ui():
    return Harness()


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:43217",
        "https://127.0.0.1:43217",
        "http://0.0.0.0:43217",
        "http://127.0.0.1",
        "http://127.0.0.1:43217/",
        "http://127.0.0.1:43217?x=y",
        "http://user@127.0.0.1:43217",
        "http://127.0.0.1:0",
    ],
)
def test_only_exact_ipv4_loopback_origin_allowed(origin):
    with pytest.raises(ValueError):
        create_app(FakeService(), origin=origin, instance_id=INSTANCE, control_secret=SECRET)


@pytest.mark.parametrize("path", ["/inbox", "/settings", "/records/ABCDEFGH"])
def test_private_reads_require_authentication(ui, path):
    assert ui.get(path).status_code == 401
    assert ui.service.calls == []


@pytest.mark.parametrize(
    "host",
    ["localhost:43217", "evil.example:43217", "127.0.0.1", "127.0.0.1:1234", "127.0.0.1.:43217"],
)
def test_host_validation_on_every_route(ui, host):
    assert ui.get("/", headers={"Host": host}).status_code == 403
    assert (
        ui.post(
            "/control/challenge", json={"operation": "open"}, headers={"Host": host}
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "https://evil.example",
        "http://localhost:43217",
        ORIGIN + "/",
        "http://127.0.0.1:9999",
    ],
)
def test_hostile_origin_rejected_including_control(ui, origin):
    assert ui.get("/", headers={"Origin": origin}).status_code == 403
    assert (
        ui.post(
            "/control/challenge", json={"operation": "open"}, headers={"Origin": origin}
        ).status_code
        == 403
    )


def test_no_proxy_or_remote_client_trust(ui):
    assert (
        ui.get(
            "/",
            environ_overrides={"REMOTE_ADDR": "192.168.1.4"},
            headers={"X-Forwarded-For": "127.0.0.1"},
        ).status_code
        == 403
    )
    assert ui.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_cli_without_origin_can_authenticate_but_browser_post_requires_origin(ui):
    challenge = ui.client.post(
        "/control/challenge",
        base_url=ORIGIN,
        json={"operation": "open", "client_nonce": new_client_nonce()},
    )
    assert challenge.status_code == 200
    response = ui.client.post("/auth/exchange", base_url=ORIGIN, json={"nonce": ui.nonce().nonce})
    assert response.status_code == 403


def test_cookie_attributes_and_reference_preserved_in_exchange(ui):
    response = ui.login("ABCDEFGH")
    assert response.json["location"] == "/records/ABCDEFGH"
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Max-Age=43200" in cookie
    assert "Path=/" in cookie and "Domain=" not in cookie
    assert "Secure" not in cookie  # Intentional canonical loopback HTTP.
    assert ui.get("/inbox").status_code == 200


@pytest.mark.parametrize(
    "reference", ["https://evil.example", "//evil", "../../settings", "ABCDEFGI"]
)
def test_exchange_rejects_arbitrary_redirect_targets(ui, reference):
    assert (
        ui.post(
            "/auth/exchange", json={"nonce": ui.nonce().nonce, "reference": reference}
        ).status_code
        == 400
    )


def test_fragment_cleared_before_fetch_and_script_has_no_external_requests(ui):
    js = ui.get("/static/app.js").text
    assert js.index("history.replaceState") < js.index('fetch("/auth/exchange"')
    assert "window.location.replace(result.location)" in js
    assert "console." not in js and "innerHTML" not in js and "http://" not in js
    assert "nonce" not in ui.get("/").text


def test_nonce_single_use_and_expiry_through_http(ui):
    nonce = ui.nonce().nonce
    ui.mono += 60
    assert ui.post("/auth/exchange", json={"nonce": nonce}).status_code == 403
    nonce = ui.nonce().nonce
    assert ui.post("/auth/exchange", json={"nonce": nonce}).status_code == 200
    assert ui.post("/auth/exchange", json={"nonce": nonce}).status_code == 403


def test_csrf_required_and_bound_to_session(ui):
    ui.login()
    other = ui.app.test_client()
    original_client = ui.client
    original_csrf = ui.csrf
    ui.client, ui.csrf = other, None
    ui.login()
    other_csrf = ui.csrf
    ui.client, ui.csrf = original_client, original_csrf
    for csrf in ("", "not-a-token", other_csrf):
        assert (
            ui.post("/records/ABCDEFGH/seen", data={}, headers={"X-CSRF-Token": csrf}).status_code
            == 403
        )
    assert not any(call[0] == "seen" for call in ui.service.calls)


def test_global_signout_revokes_two_clients(ui):
    ui.login()
    first = ui.client
    second = ui.app.test_client()
    ui.client, ui.csrf = second, None
    ui.login()
    assert ui.post("/auth/signout", data={}).status_code == 303
    assert first.get("/inbox", base_url=ORIGIN).status_code == 401
    assert second.get("/inbox", base_url=ORIGIN).status_code == 401


def test_cookie_expires_without_sliding_renewal(ui):
    ui.login()
    ui.mono += 43199
    assert ui.get("/inbox").status_code == 200
    ui.mono += 1
    assert ui.get("/inbox").status_code == 401


def test_restart_app_rejects_prior_cookie(ui):
    ui.login()
    old_cookie = ui.client.get_cookie(COOKIE_NAME, domain="127.0.0.1")
    other = Harness()
    other.client.set_cookie(COOKIE_NAME, old_cookie.value, domain="127.0.0.1")
    assert other.get("/inbox").status_code == 401


def test_security_headers_no_cors_no_secret_disclosure(ui):
    for path in ("/", "/static/app.js", "/inbox"):
        response = ui.get(path)
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "same-origin"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]
        assert "Access-Control-Allow-Origin" not in response.headers
        assert SECRET.decode() not in response.text and SECRET.hex() not in response.text


def test_signed_stop_callback_only_after_authentication():
    calls = []
    ui = Harness(request_stop=lambda: calls.append("queued"))
    result = ui.post(
        "/control/stop",
        json={
            "operation": "stop",
            "challenge": "A" * 43 + "." + "B" * 43,
            "instance_id": INSTANCE,
            "mac": "0" * 64,
        },
    )
    assert result.status_code == 403 and not calls
    reply = ui.nonce("stop")
    assert reply.result == "stopping" and reply.nonce == "" and calls == ["queued"]


@pytest.mark.parametrize(
    "path",
    [
        "/approve",
        "/resume",
        "/producer",
        "/control/eval",
        "/records/ABCDEFGH/approve",
        "/records/ABCDEFGH/resume",
    ],
)
def test_no_approval_producer_or_arbitrary_dispatch(ui, path):
    ui.login()
    assert ui.post(path, data={}).status_code == 404


def test_settings_revision_validation_and_bounded_interval(ui):
    ui.login()
    assert (
        ui.post(
            "/settings",
            json={
                "expected_revision": 0,
                "changes": {
                    "local_layout": "compact",
                    "delivery_mode": "digest",
                    "digest_interval_minutes": 1440,
                    "global_pause": True,
                },
            },
        ).status_code
        == 303
    )
    assert ui.service.settings.local_layout.value == "compact"
    assert ui.service.settings.global_pause
    assert (
        ui.post(
            "/settings", json={"expected_revision": 0, "changes": {"global_pause": False}}
        ).status_code
        == 409
    )
    assert ui.service.settings.global_pause


@pytest.mark.parametrize(
    "changes",
    [
        {"digest_interval_minutes": 0},
        {"digest_interval_minutes": 1441},
        {"digest_interval_minutes": True},
        {"digest_interval_minutes": "10"},
        {"local_layout": "javascript:alert(1)"},
        {"global_pause": "false"},
        {"destination_generation": 55},
        {"provider_suspended": False},
        {"destination": {}},
        {"device_alias": "bad\nname"},
        {"global_pause": None},
    ],
)
def test_invalid_settings_never_reach_writer(ui, changes):
    ui.login()
    assert (
        ui.post("/settings", json={"expected_revision": 0, "changes": changes}).status_code == 400
    )
    assert ui.service.settings.revision == 0


def test_disclosure_requires_exact_session_and_revision_preview(ui):
    ui.login()
    body = {"expected_revision": 0, "changes": {"disclosure_fields": ["action"]}}
    assert ui.post("/settings", json=body).status_code == 409
    preview = ui.post("/settings/preview", json=body)
    assert preview.status_code == 200 and ui.service.settings.revision == 0
    text = preview.json["previews"][0]
    assert "Task: Example task description" in text and "Example reason" not in text
    receipt = preview.json["preview_receipt"]
    changed = body | {
        "changes": {"disclosure_fields": ["action", "reason"]},
        "preview_receipt": receipt,
    }
    assert ui.post("/settings", json=changed).status_code == 409
    assert ui.post("/settings", json=body | {"preview_receipt": receipt}).status_code == 303
    assert {field.value for field in ui.service.settings.disclosure_fields} == {"action"}
    assert ui.post("/settings", json=body | {"preview_receipt": receipt}).status_code == 409


def test_alias_edit_revision_and_local_path_visible_only_after_auth(ui):
    assert "C:/Local/Example" not in ui.get("/settings").text
    ui.login()
    assert "C:/Local/Example" in ui.get("/settings").text
    assert (
        ui.post(
            "/settings/alias",
            data={"identity": "identity-one", "alias": "My project", "expected_revision": "0"},
        ).status_code
        == 303
    )
    assert ui.service.aliases[0].alias == "My project"
    assert (
        ui.post(
            "/settings/alias",
            data={"identity": "identity-one", "alias": "Stale", "expected_revision": "0"},
        ).status_code
        == 409
    )


def test_all_history_reference_search_independent_empty_filter(ui):
    historic = view("BCDEFGHJ", PresentationStatus.OBSERVATION_AGED)
    ui.service.records = {historic.short_reference: historic}
    ui.login()
    html = ui.get("/inbox").text
    assert "1 observations aged without a verified outcome" in html
    assert "they may still be waiting in Codex" in html
    assert "No records on this page" in html
    result = ui.get("/inbox?filter=attention&cursor=999&short_reference=bcdefghj")
    assert result.status_code == 303 and result.location == "/records/BCDEFGHJ"
    assert "Observation aged; current state unverified" in ui.get(result.location).text


def test_counts_are_full_store_not_page_length(ui):
    ui.login()
    original = ui.service.snapshot

    def one_page(**kwargs):
        return replace(original(**kwargs), counts=InboxCounts(attention=73), next_cursor="page-two")

    ui.service.snapshot = one_page
    html = ui.get("/inbox").text
    assert 'class="count">73</span>' in html
    assert "This page contains 1 records" in html and "cursor=page-two" in html
    assert ui.service.calls[-1] == ("snapshot", "attention", None, 50)


def test_confirmed_counts_and_seen_visibility_remain_distinct(ui):
    confirmed = view("BCDEFGHJ", PresentationStatus.CURRENT_CONFIRMED_PENDING)
    ui.service.records[confirmed.short_reference] = confirmed
    ui.service.supported = True
    ui.login()
    assert "Source-confirmed pending" in ui.get("/inbox").text
    for ref in ("ABCDEFGH", "BCDEFGHJ"):
        assert ui.post(f"/records/{ref}/seen", data={}).status_code == 303
    html = ui.get("/inbox").text
    assert "/records/BCDEFGHJ" in html and "/records/ABCDEFGH" not in html
    assert "Waiting for you (confirmed by Codex)" in html and "Seen" in html
    assert ui.service.records["BCDEFGHJ"].source_state == "pending"


def test_unsupported_confirmed_filter_hidden_and_gate_never_attention(ui):
    gate = view("BCDEFGHJ", PresentationStatus.GATE_OBSERVED)
    ui.service.records = {gate.short_reference: gate}
    ui.login()
    html = ui.get("/inbox").text
    assert "Source-confirmed pending" not in html and "/records/BCDEFGHJ" not in html
    assert "Gate observed; no prompt confirmed" in ui.get("/inbox?filter=unverified").text


def test_snooze_hides_without_source_expiry_extension_and_suppress_is_distinct(ui):
    ui.login()
    original = ui.service.records["ABCDEFGH"]
    detail = ui.get("/records/ABCDEFGH").text
    assert "Hide (no reminder) · 1 hour" in detail
    assert ui.post("/records/ABCDEFGH/snooze", data={"duration": "60"}).status_code == 303
    snoozed = ui.service.records["ABCDEFGH"]
    assert snoozed.aging_deadline == original.aging_deadline
    assert snoozed.source_state == original.source_state and not snoozed.needs_attention
    assert ui.post("/records/ABCDEFGH/suppress", data={"suppressed": "true"}).status_code == 303
    assert ui.service.records["ABCDEFGH"].suppressed
    assert ui.service.records["ABCDEFGH"].snoozed_until == snoozed.snoozed_until


@pytest.mark.parametrize(
    "until", ["bad", "2026-10-04T11:00:00", "2026-10-04T10:00:00Z", "2026-10-03T23:00:00Z"]
)
def test_custom_snooze_rejects_invalid_naive_or_nonfuture_time(ui, until):
    ui.login()
    assert (
        ui.post("/records/ABCDEFGH/snooze", data={"duration": "custom", "until": until}).status_code
        == 400
    )
    assert ui.service.records["ABCDEFGH"].snoozed_until is None


def test_custom_snooze_preserves_timezone_and_gets_do_not_mutate(ui):
    ui.login()
    assert (
        ui.post(
            "/records/ABCDEFGH/snooze",
            data={"duration": "custom", "until": "2026-10-04T16:00:00+05:30"},
        ).status_code
        == 303
    )
    assert ui.service.records["ABCDEFGH"].snoozed_until == NOW + timedelta(minutes=30)
    before = dict(ui.service.records)
    for path in ("/inbox", "/records/ABCDEFGH", "/settings"):
        assert ui.get(path).status_code == 200
    assert ui.service.records == before
    assert ui.get("/records/ABCDEFGH/seen").status_code == 405


@pytest.mark.parametrize(
    "layout,marker,absent",
    [
        ("friendly", 'class="context-blocks"', 'class="short-action"'),
        ("compact", 'class="short-action"', 'class="context-blocks"'),
    ],
)
def test_two_structural_layouts_accessibility_and_safe_text(ui, layout, marker, absent):
    ui.service.settings = revised_settings(ui.service.settings, {"local_layout": layout})
    row = ui.service.records["ABCDEFGH"]
    attack = '<script>alert("source")</script><img src=https://evil.test/x>'
    p = row.presentation.model_copy(update={"action": attack})
    ui.service.records["ABCDEFGH"] = replace(row, presentation=p)
    ui.login()
    html = ui.get("/inbox").text
    assert marker in html and absent not in html
    assert '<script>alert("source")' not in html and "&lt;script&gt;" in html
    assert 'class="skip-link"' in html and '<main id="main" tabindex="-1">' in html
    assert 'aria-label="Inbox filters"' in html and 'aria-current="page"' in html
    assert '<meta name="viewport"' in html
    css = ui.get("/static/app.css").text
    assert ":focus-visible" in css and "@media (max-width:650px)" in css


class Resources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for key in ("src", "href", "action"):
            if key in values:
                self.targets.append(values[key])
        if tag == "input" and values.get("name"):
            self.inputs[values["name"]] = values.get("value", "")


def test_no_external_assets_and_source_url_never_native_link(ui):
    row = ui.service.records["ABCDEFGH"]
    p = row.presentation.model_copy(
        update={"source_reference": "javascript:alert(1)", "source_path": "https://evil.test/"}
    )
    ui.service.records["ABCDEFGH"] = replace(row, presentation=p)
    ui.login()
    html = ui.get("/records/ABCDEFGH").text
    links = Resources()
    links.feed(html)
    assert all(target.startswith(("/", "#")) for target in links.targets)
    assert "Copy chat reference" in html and "Open chat in Codex" not in html
    assert "Mark as seen (does not answer the agent)" in html
    assert ">Approve<" not in html and ">Resume<" not in html


def test_qualified_structured_uuid_only_native_link(ui):
    row = ui.service.records["ABCDEFGH"]
    native = NativeChatReference(
        thread_id=UUID("00000000-0000-4000-8000-000000000001"), navigation_qualified=True
    )
    ui.service.records["ABCDEFGH"] = replace(
        row, presentation=row.presentation.model_copy(update={"native_reference": native})
    )
    ui.login()
    html = ui.get("/records/ABCDEFGH").text
    assert 'href="codex://threads/00000000-0000-4000-8000-000000000001"' in html
    # This synthetic fixture does not qualify real native navigation.


def test_missing_snapshot_does_not_invent_kind_or_pruning_story(ui):
    row = ui.service.records["ABCDEFGH"]
    ui.service.records["ABCDEFGH"] = replace(row, presentation=None, detail_available=False)
    ui.login()
    html = ui.get("/records/ABCDEFGH").text
    assert "Request details unavailable" in html
    assert "Details no longer available" not in html and "pruned" not in html
    assert "Copy chat reference" in html and "ABCDEFGH" in html


def test_setup_unavailable_is_honest_and_no_send_or_callback_dispatch(ui):
    ui.login()
    html = ui.get("/settings").text
    assert "Telegram setup is unavailable" in html
    assert "No test send is available" in html
    assert ui.post("/setup/token", data={"token": "not-real"}).status_code == 503
    assert ui.post("/setup/send-test", data={"preview_id": "anything"}).status_code == 409


def test_setup_token_secret_and_exact_selected_preview_only():
    calls = []
    current = SetupView(
        stage="paired",
        message="Awaiting explicit test action",
        recipient="123",
        preview="Decision Mesh synthetic test",
        preview_id="preview-one",
        can_send_test=True,
    )

    def configure(token):
        assert token.get_secret_value() == "fake-secret"
        calls.append("token")
        return replace(current, message="Token validated; setup remains incomplete")

    def send(preview_id):
        calls.append(preview_id)
        return replace(current, stage="test_incomplete", message="Synthetic test callback ran")

    ui = Harness(setup=SetupCallbacks(lambda: current, configure_token=configure, send_test=send))
    ui.login()
    html = ui.post("/setup/token", data={"token": "fake-secret"}).text
    assert "fake-secret" not in html and calls == ["token"]
    assert ui.post("/setup/send-test", data={"preview_id": "stale"}).status_code == 409
    assert ui.post("/setup/send-test", data={"preview_id": "preview-one"}).status_code == 200
    assert calls == ["token", "preview-one"]


def test_redacts_callback_errors_and_no_false_setup_success():
    def fail(_token):
        raise RuntimeError("do-not-leak-bot-token")

    ui = Harness(setup=SetupCallbacks(lambda: SetupView(), configure_token=fail))
    ui.login()
    response = ui.post("/setup/token", data={"token": "do-not-leak-bot-token"})
    assert response.status_code == 503
    assert "do-not-leak-bot-token" not in response.text
    assert "No success was recorded" not in response.text
    assert "outcome could not be confirmed" in response.text


@pytest.mark.parametrize(
    "failure_stage", ["snapshot_after_effect", "callback_after_effect", "before_callback"]
)
def test_setup_send_service_failure_preserves_outcome_uncertainty(monkeypatch, failure_stage):
    completed_tests = []
    current = SetupView(stage="paired", preview_id="preview-one", can_send_test=True)
    service = FakeService()

    def unavailable(**_kwargs):
        raise RuntimeError("synthetic-private-service-detail")

    def status():
        if failure_stage == "before_callback":
            unavailable()
        return current

    def send(preview_id):
        completed_tests.append(preview_id)
        if failure_stage == "callback_after_effect":
            unavailable()
        monkeypatch.setattr(service, "snapshot", unavailable)
        return replace(current, stage="test_complete", message="Synthetic test completed")

    ui = Harness(service=service, setup=SetupCallbacks(status, send_test=send))
    ui.login()
    response = ui.post("/setup/send-test", data={"preview_id": "preview-one"})

    assert response.status_code == 503
    assert completed_tests == ([] if failure_stage == "before_callback" else ["preview-one"])
    assert "No success was recorded" not in response.text
    assert "outcome could not be confirmed" in response.text
    assert "Reload its status before retrying" in response.text
    assert "it may have completed" in response.text
    assert "synthetic-private-service-detail" not in response.text
    assert SECRET.decode() not in response.text
    assert "Synthetic test completed" not in response.text


def test_retry_duplicate_ack_and_resume_injected_explicitly():
    calls = []
    ui = Harness(
        delivery=DeliveryCallbacks(
            manual_retry=lambda occurrence, **kwargs: calls.append((occurrence, kwargs)),
            resume_route=lambda: calls.append("resume-notifications"),
        )
    )
    ui.service.deliveries = (
        DeliveryView("occurrence-one", ("ABCDEFGH",), "outcome_unknown", 6, True, True),
    )
    ui.service.settings = revised_settings(ui.service.settings, {"provider_suspended": True})
    ui.login()
    html = ui.get("/settings").text
    assert "I understand this retry may duplicate a message" in html
    assert "Resume notifications after repairing the route" in html
    assert (
        ui.post("/delivery/occurrence-one/retry", data={"acknowledge_duplicate": "on"}).status_code
        == 303
    )
    assert calls == [("occurrence-one", {"acknowledge_duplicate": True})]
    assert ui.post("/delivery/resume-notifications", data={}).status_code == 303
    assert calls[-1] == "resume-notifications"


def test_html_settings_preview_confirmation_roundtrip(ui):
    ui.login()
    response = ui.post(
        "/settings/preview",
        data={
            "expected_revision": "0",
            "local_layout": "compact",
            "telegram_layout": "friendly",
            "delivery_mode": "digest",
            "digest_interval_minutes": "10",
            "device_alias": "My computer",
            "fields": "reason",
        },
    )
    assert response.status_code == 200
    assert "Example reason" in response.text and "No message has been sent" in response.text
    assert ui.service.settings.revision == 0
    parsed = Resources()
    parsed.feed(response.text)
    assert ui.post("/settings", data=parsed.inputs).status_code == 303
    assert ui.service.settings.local_layout.value == "compact"
    assert ui.service.settings.device_alias == "My computer"


def test_real_storage_view_integration_without_competing_writer(
    tmp_path, now, explicit_capabilities, event_factory
):
    from decision_mesh.storage import SQLiteStore

    with SQLiteStore(tmp_path / "ui-integration" / "mesh.db", now=now) as store:
        store.register_source(explicit_capabilities)
        receipt = store.ingest(
            event_factory(snapshot_changes={"action": "Choose a test target"}), received_at=now
        )
        stored = store.get_record(receipt.record_id)
        row = record_view(stored, now=now, allowed_fields=LOCAL_FIELDS, include_local_details=True)
        ui = Harness(FakeService([row]))
        ui.login()
        html = ui.get(f"/records/{receipt.short_reference}").text
        assert "Agent-reported question (not verified)" in html
        assert stored.projection.snapshot.action in html
        assert "Choose a test target" in html and "A or B?" in html
        assert receipt.short_reference in html
        assert store.get_record(receipt.record_id) == stored


def test_reviewable_synthetic_layout_fixtures_match():
    # Frozen synthetic review evidence; normal test runs never rewrite source fixtures.
    directory = Path(__file__).parent / "fixtures" / "ui"
    for layout in ("friendly", "compact"):
        ui = Harness()
        ui.service.settings = revised_settings(ui.service.settings, {"local_layout": layout})
        ui.login()
        html = ui.get("/inbox").text
        html = html.replace(ui.csrf, "REDACTED_SYNTHETIC_CSRF")
        assert (directory / f"{layout}.html").read_text(encoding="utf-8") == html


def test_non_ascii_csrf_rejected_without_server_error(ui):
    ui.login()
    assert (
        ui.post("/records/ABCDEFGH/seen", data={}, headers={"X-CSRF-Token": "é" * 43}).status_code
        == 403
    )


def test_client_nonce_required_no_old_server_only_handshake(ui):
    assert ui.post("/control/challenge", json={"operation": "open"}).status_code == 400


def test_disclosure_preview_receipt_rejects_other_browser_session(ui):
    ui.login()
    data = {"expected_revision": 0, "changes": {"disclosure_fields": ["action"]}}
    receipt = ui.post("/settings/preview", json=data).json["preview_receipt"]
    ui.client, ui.csrf = ui.app.test_client(), None
    ui.login()
    assert ui.post("/settings", json=data | {"preview_receipt": receipt}).status_code == 409
    assert not ui.service.settings.disclosure_fields


def test_snapshot_bound_fails_closed_and_redacted(ui):
    ui.login()
    original = ui.service.snapshot
    ui.service.snapshot = lambda **kwargs: replace(original(**kwargs), records=(view(),) * 51)
    response = ui.get("/inbox")
    assert response.status_code == 503 and "invalid_snapshot" not in response.text


def test_local_question_fields_escaped_and_not_shared_by_external_preview(ui):
    row = ui.service.records["ABCDEFGH"]
    details = LocalDetails(
        title="Question <script>bad()</script>",
        summary="Local summary only",
        task="Local task context",
        options=("A <img src=x>", "B"),
        exclusions="No changes outside the task",
    )
    ui.service.records["ABCDEFGH"] = replace(row, local_details=details)
    ui.login()
    html = ui.get("/records/ABCDEFGH").text
    assert "Question &lt;script&gt;bad()&lt;/script&gt;" in html
    assert "A &lt;img src=x&gt;" in html and "Local summary only" in html
    assert "Local summary only" not in ui.get("/settings").text


def test_include_current_requires_explicit_selection_and_injected_worker():
    calls = []
    ui = Harness(delivery=DeliveryCallbacks(include_current=lambda ids: calls.append(ids)))
    ui.login()
    assert (
        "Reactivation never forwards an older backlog automatically"
        in ui.get("/records/ABCDEFGH").text
    )
    assert ui.post("/records/ABCDEFGH/include-current", data={}).status_code == 400
    assert not calls
    assert ui.post("/records/ABCDEFGH/include-current", data={"confirm": "on"}).status_code == 303
    assert calls == [("record-ABCDEFGH",)]


@pytest.mark.parametrize(
    "path",
    ["/records/ABCDEFGH/seen", "/settings", "/setup/token", "/delivery/resume-notifications"],
)
def test_unauthenticated_mutations_never_reach_callbacks(ui, path):
    assert ui.post(path, data={}).status_code == 401
    assert ui.service.calls == []


def test_real_store_metadata_mutations_preserve_source_state(
    tmp_path, now, explicit_capabilities, event_factory
):
    from decision_mesh.storage import SQLiteStore

    with SQLiteStore(tmp_path / "ui-mutations" / "mesh.db", now=now) as store:
        store.register_source(explicit_capabilities)
        receipt = store.ingest(event_factory(), received_at=now)
        before = store.get_record(receipt.record_id).projection

        class TestFacade(FakeService):
            def lookup_reference(self, reference, *, now):
                stored = store.lookup_reference(reference)
                return (
                    record_view(
                        stored, now=now, allowed_fields=LOCAL_FIELDS, include_local_details=True
                    )
                    if stored
                    else None
                )

            def mark_seen(self, record_id, *, now):
                store.set_record_metadata(record_id, seen=True, now=now)

            def snooze(self, record_id, until, *, now):
                store.set_record_metadata(record_id, snoozed_until=until, now=now)

            def set_suppressed(self, record_id, suppressed, *, now):
                store.set_record_metadata(record_id, suppressed=suppressed, now=now)

        ui = Harness(TestFacade())
        ui.login()
        ref = receipt.short_reference
        assert ui.post(f"/records/{ref}/seen", data={}).status_code == 303
        assert ui.post(f"/records/{ref}/snooze", data={"duration": "60"}).status_code == 303
        assert ui.post(f"/records/{ref}/suppress", data={"suppressed": "true"}).status_code == 303
        after = store.get_record(receipt.record_id)
        assert after.projection == before
        assert after.seen and after.suppressed
        assert after.snoozed_until == now + timedelta(hours=1)


@pytest.mark.parametrize("origin", [None, "null", "https://evil.example", "http://127.0.0.1:9999"])
def test_authenticated_form_requires_exact_origin_despite_valid_session_and_csrf(ui, origin):
    ui.login()
    before = ui.service.records["ABCDEFGH"]
    headers = {} if origin is None else {"Origin": origin}
    response = ui.client.post(
        "/records/ABCDEFGH/seen",
        base_url=ORIGIN,
        headers=headers,
        data={"csrf": ui.csrf},
    )
    assert response.status_code == 403
    assert ui.service.records["ABCDEFGH"] == before
    assert not any(call[0] == "seen" for call in ui.service.calls)
