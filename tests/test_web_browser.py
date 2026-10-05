"""Optional Chromium regressions for real forms and intrinsic layout sizing.

Requires an existing Playwright install and cached Chromium; never installs either.
Only synthetic data, a fake service, and a fresh browser context are used.
These source checks do not establish the complete installed-runtime/wheel journey.
"""

import json
import threading
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from test_web import INSTANCE, NOW, SECRET, FakeService
from werkzeug.serving import WSGIRequestHandler, make_server

from decision_mesh.control import new_client_nonce, request_mac, verify_challenge, verify_response
from decision_mesh.settings import revised_settings
from decision_mesh.view import LocalDetails
from decision_mesh.web import create_app


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        pass


@pytest.fixture
def live_ui():
    service = FakeService()
    row = service.records["ABCDEFGH"]
    service.records["ABCDEFGH"] = replace(
        row,
        local_details=LocalDetails(
            title="Synthetic question", summary="W" * 180, task=None, options=(), exclusions=None
        ),
    )
    server = make_server("127.0.0.1", 0, lambda *_args: [], request_handler=QuietHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_app(
        service, origin=origin, instance_id=INSTANCE, control_secret=SECRET, clock=lambda: NOW
    )
    server.app = app
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield service, app, origin
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()
        assert not thread.is_alive()


@pytest.fixture
def browser():
    playwright = pytest.importorskip("playwright.sync_api", reason="optional real browser checks")
    with playwright.sync_playwright() as tool, tool.chromium.launch(headless=True) as instance:
        yield instance


@pytest.fixture
def browser_page(browser, live_ui):
    _service, _app, origin = live_ui
    blocked, errors = [], []
    with browser.new_context(
        viewport={"width": 1280, "height": 900}, service_workers="block", reduced_motion="reduce"
    ) as context:

        def local_only(route):
            url = urlsplit(route.request.url)
            if f"{url.scheme}://{url.netloc}" == origin:
                route.continue_()
            else:
                blocked.append(url.scheme)
                route.abort()

        context.route("**/*", local_only)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        yield page
        assert not blocked
        assert not errors


def login(page, live_ui):
    _service, app, origin = live_ui
    client_nonce = new_client_nonce()
    with app.test_client() as client:
        data = client.post(
            "/control/challenge",
            base_url=origin,
            json={"operation": "open", "client_nonce": client_nonce},
        ).get_json()
        challenge = verify_challenge(data, client_nonce=client_nonce, instance_id=INSTANCE)
        data = client.post(
            "/control/open",
            base_url=origin,
            json={
                "operation": "open",
                "challenge": challenge,
                "instance_id": INSTANCE,
                "mac": request_mac(SECRET, "open", challenge, INSTANCE),
            },
        ).get_json()
        reply = verify_response(
            SECRET, data, operation="open", challenge=challenge, instance_id=INSTANCE
        )
    page.goto(origin + "/#nonce=" + reply.nonce)
    page.wait_for_url(origin + "/inbox")
    assert page.evaluate("location.hash") == ""
    assert "decision_mesh_session" not in page.evaluate("document.cookie")


def test_browser_forms_preserve_origin_and_authority(browser_page, live_ui):
    service, _app, origin = live_ui
    page = browser_page
    forms = []

    def observe(response):
        if response.request.method == "POST":
            headers = response.request.all_headers()
            forms.append((urlsplit(response.url).path, response.status, headers.get("origin")))

    page.on("response", observe)
    login(page, live_ui)
    before = service.records["ABCDEFGH"]
    page.goto(origin + "/settings")
    page.locator("#local-layout").select_option("compact")
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/settings/preview"
    ) as preview:
        page.get_by_role("button", name="Review changes and external preview").click()
    assert preview.value.status == 200
    page.get_by_role("button", name="Confirm preview and save settings").click()
    assert service.settings.local_layout.value == "compact"
    page.goto(origin + "/records/ABCDEFGH")

    # Negative requests include the real session and a legitimate CSRF field.
    # They must not reach the fake service mutation even after the policy repair.
    csrf = page.locator('form[action$="/seen"] input[name="csrf"]').input_value()
    for supplied_origin, supplied_csrf in [
        ("null", csrf),
        ("https://evil.example", csrf),
        (origin, "wrong"),
    ]:
        response = page.context.request.post(
            origin + "/records/ABCDEFGH/seen",
            headers={"Origin": supplied_origin},
            form={"csrf": supplied_csrf},
        )
        assert response.status == 403
    assert service.records["ABCDEFGH"] == before

    page.get_by_role("button", name="Mark as seen (does not answer the agent)", exact=True).click()
    assert service.records["ABCDEFGH"].seen
    page.get_by_role("button", name="Snooze " + chr(183) + " 10 minutes", exact=True).click()
    assert service.records["ABCDEFGH"].snoozed_until is not None
    page.get_by_role("button", name="Suppress notifications for this record", exact=True).click()
    after = service.records["ABCDEFGH"]
    assert after.suppressed
    for field in ("source_state", "evidence_class", "execution_state", "aging_deadline"):
        assert getattr(after, field) == getattr(before, field)
    page.get_by_role("button", name="Sign out all sessions", exact=True).click()
    response = page.goto(origin + "/inbox")
    assert response.status == 401
    expected = [
        ("/settings/preview", 200),
        ("/settings", 303),
        ("/records/ABCDEFGH/seen", 303),
        ("/records/ABCDEFGH/snooze", 303),
        ("/records/ABCDEFGH/suppress", 303),
        ("/auth/signout", 303),
    ]
    assert [(path, status) for path, status, _ in forms if path != "/auth/exchange"] == expected
    assert all(supplied == origin for _, _, supplied in forms)


@pytest.mark.parametrize("layout", ["friendly", "compact"])
def test_browser_layout_fits_without_clipping_and_keeps_focus(
    browser_page, live_ui, tmp_path, layout
):
    service, _app, origin = live_ui
    service.settings = revised_settings(service.settings, {"local_layout": layout})
    page = browser_page
    login(page, live_ui)
    measurements = []
    for width in (320, 390, 1280):
        page.set_viewport_size({"width": width, "height": 900})
        for path in ("/inbox", "/records/ABCDEFGH", "/settings"):
            page.goto(origin + path)
            measured = page.evaluate("""() => ({
                document: document.documentElement.scrollWidth,
                body: document.body.scrollWidth,
                clipped: [...document.querySelectorAll('html,body,main,form,fieldset')]
                    .some(el => ['hidden','clip'].includes(getComputedStyle(el).overflowX)),
                overflow: [...document.querySelectorAll('main *')].filter(el => {
                    const box = el.getBoundingClientRect();
                    return box.width && (box.left < 0 || box.right > innerWidth + 1);
                }).map(el => el.id || el.tagName)
            })""")
            measurements.append({"layout": layout, "width": width, "path": path, **measured})
            assert measured["document"] == width, measurements[-1]
            assert measured["body"] == width, measurements[-1]
            assert not measured["clipped"], measurements[-1]
            assert not measured["overflow"], measurements[-1]
            selector = (
                "#until"
                if path.startswith("/records")
                else "#device-alias"
                if path == "/settings"
                else 'input[name="short_reference"]'
            )
            control = page.locator(selector)
            page.keyboard.press("Tab")
            control.focus()
            focus = control.evaluate("""el => ({
                active: el === document.activeElement,
                style: getComputedStyle(el).outlineStyle,
                width: parseFloat(getComputedStyle(el).outlineWidth)
            })""")
            assert focus["active"] and focus["style"] != "none" and focus["width"] >= 3
            if width == 390:
                # Capture from the top so off-viewport fixed UI stays outside the image.
                page.evaluate("window.scrollTo(0, 0)")
                page.screenshot(
                    path=str(tmp_path / f"{layout}-{path.rsplit('/', 1)[-1]}.png"), full_page=True
                )
    (tmp_path / "measurements.json").write_text(
        json.dumps(measurements, indent=2) + "\n", encoding="utf-8"
    )
