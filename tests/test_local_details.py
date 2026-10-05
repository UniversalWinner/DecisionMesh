"""Authenticated local claims stay distinct from authority and external disclosure."""

import json
from dataclasses import asdict, replace
from datetime import timedelta

import pytest
from markupsafe import escape
from test_web import FakeService, Harness, Resources

# Explicit fixture re-exports let pytest resolve transitive browser dependencies.
from test_web_browser import browser as browser  # noqa: PLC0414
from test_web_browser import browser_page as browser_page  # noqa: PLC0414
from test_web_browser import live_ui as live_ui  # noqa: PLC0414
from test_web_browser import login

from decision_mesh.presentation.models import DisclosedField
from decision_mesh.presentation.renderers import render_telegram_parts
from decision_mesh.settings import CapturePolicy, DestinationIdentity, Settings, revised_settings
from decision_mesh.storage import SQLiteStore
from decision_mesh.view import LocalDetails, record_view, to_external_record, to_presentation_record
from decision_mesh.web import LOCAL_FIELDS

REFERENCE = {
    "source_pointer": "https://source.invalid/private-claim",
    "quote": "PRIVATE authority quote",
    "scope": "PRIVATE authority scope",
    "exclusions": "PRIVATE authority exclusions",
    "supplied_lifetime": "PRIVATE authority lifetime",
    "asserted_by": "agent",
}


@pytest.fixture
def stored_factory(tmp_path, now, event_factory, explicit_capabilities, native_capabilities):
    with SQLiteStore(tmp_path / "claims" / "mesh.db", now=now) as store:
        store.register_source(explicit_capabilities)
        # Synthetic enrollment only; this fixture does not qualify an installed host.
        store.register_source(native_capabilities, enabled=True, qualified=True)

        def make(*, native=False, **changes):
            event = event_factory(native=native, snapshot_changes=changes)
            receipt = store.ingest(event, received_at=now)
            return store, store.get_record(receipt.record_id)

        yield make


def local_page(stored, now, layout="friendly"):
    row = record_view(stored, now=now, allowed_fields=LOCAL_FIELDS, include_local_details=True)
    ui = Harness(FakeService([row]))
    ui.service.settings = revised_settings(ui.service.settings, {"local_layout": layout})
    assert ui.get(f"/records/{row.short_reference}").status_code == 401
    ui.login()
    response = ui.get(f"/records/{row.short_reference}")
    assert response.status_code == 200
    return row, response.text


def test_mapper_claims_require_local_opt_in_and_preserve_values(stored_factory, now):
    _store, stored = stored_factory(
        gate_kind="technical_review",
        action_category="testing",
        authority_reference=REFERENCE,
        source_expiry=now - timedelta(days=1),
    )
    assert record_view(stored, now=now).local_details is None
    local = record_view(stored, now=now, include_local_details=True).local_details
    assert local.gate_kind == "technical_review"
    assert local.action_category == "testing"
    assert local.authority_reference.model_dump() == REFERENCE
    assert local.source_expiry == now - timedelta(days=1)
    assert stored.projection.source_state.value == "unverified"
    assert stored.projection.execution_state.value == "not_observed"


def test_local_details_new_defaults_preserve_existing_fixtures():
    local = LocalDetails("Title", "Summary", None, (), None)
    assert local.gate_kind == "unclassified"
    assert local.action_category == "unknown"
    assert local.authority_reference is None
    assert local.source_expiry is None


@pytest.mark.parametrize("layout", ["friendly", "compact"])
@pytest.mark.parametrize(
    "gate,action,gate_label,action_label",
    [
        ("user_authority", "testing", "User authority", "Testing"),
        ("technical_review", "implementation", "Technical review", "Implementation"),
        ("platform_permission", "download", "Platform permission", "Download"),
        ("runtime_admission", "installation", "Runtime admission", "Installation"),
        ("unclassified", "general", "Unclassified", "General"),
        ("unclassified", "unknown", "Unclassified", "Unknown"),
    ],
)
def test_gate_and_action_labels_are_reported_claims(
    stored_factory, now, layout, gate, action, gate_label, action_label
):
    store, stored = stored_factory(gate_kind=gate, action_category=action)
    before = stored.projection
    row, html = local_page(stored, now, layout)
    assert "Gate category (reported)" in html and f"<dd>{gate_label}</dd>" in html
    assert "Action category (reported)" in html and f"<dd>{action_label}</dd>" in html
    assert "They do not establish permission or a verified review result." in html
    assert "Authority reference not supplied" in html
    assert row.source_state == "unverified" and row.execution_state == "not_observed"
    assert store.get_record(stored.projection.record_id).projection == before


@pytest.mark.parametrize("layout", ["friendly", "compact"])
@pytest.mark.parametrize("asserted_by", ["agent", "user", "host"])
def test_supplied_assertor_is_not_verified_identity(stored_factory, now, layout, asserted_by):
    _store, stored = stored_factory(
        native=asserted_by == "host",
        authority_reference=REFERENCE | {"asserted_by": asserted_by},
    )
    _row, html = local_page(stored, now, layout)
    assert "Authority reference (source/agent claim)" in html
    assert "Assertion origin (supplied)" in html
    assert f"<dd>{asserted_by.capitalize()}</dd>" in html
    assert "The assertion origin is a supplied label, not a verified identity." in html
    assert "This reference is a source/agent claim, not an approval or executable policy." in html
    for key in ("source_pointer", "quote", "scope", "exclusions", "supplied_lifetime"):
        assert str(escape(REFERENCE[key])) in html


@pytest.mark.parametrize("authority", [None, {"asserted_by": "agent", "quote": "Only a quote"}])
def test_missing_fields_remain_unknown_and_action_does_not_infer_gate(
    stored_factory, now, authority
):
    _store, stored = stored_factory(action_category="installation", authority_reference=authority)
    row, html = local_page(stored, now)
    assert row.local_details.gate_kind == "unclassified"
    assert "<dd>Unclassified</dd>" in html
    assert "<dd>Installation</dd>" in html
    assert "Not supplied" in html
    assert "<dd>User authority</dd>" not in html
    if authority:
        assert "Only a quote" in html
        assert html.count("<dd>Not supplied</dd>") >= 4
    else:
        assert "Authority reference not supplied" in html


@pytest.mark.parametrize("delta", [timedelta(days=-1), timedelta(days=1)])
def test_source_expiry_is_only_supplied_metadata(stored_factory, now, delta):
    store, stored = stored_factory(source_expiry=now + delta)
    before = stored.projection
    row, html = local_page(stored, now)
    assert "Source-supplied expiry" in html and (now + delta).isoformat() in html
    assert "A supplied timestamp does not establish current source expiry." in html
    assert row.source_state == "unverified" and not row.history
    assert row.evidence_label == "Agent-reported question (not verified)"
    assert store.get_record(stored.projection.record_id).projection == before


@pytest.mark.parametrize("layout", ["friendly", "compact"])
def test_authority_values_render_as_escaped_text_without_active_urls(stored_factory, now, layout):
    hostile = '<script>window.bad=1</script><a href="javascript:bad()">claim</a>'
    authority = {key: hostile + "/" + key for key in REFERENCE if key != "asserted_by"}
    authority["asserted_by"] = "agent"
    _store, stored = stored_factory(authority_reference=authority)
    _row, html = local_page(stored, now, layout)
    for key, value in authority.items():
        if key != "asserted_by":
            assert str(escape(value)) in html
    assert "<script>window.bad" not in html
    links = Resources()
    links.feed(html)
    assert all(target.startswith(("/", "#")) for target in links.targets)


@pytest.mark.parametrize("keep_snapshot", [False, True])
def test_pruned_detail_hides_all_private_claims(stored_factory, now, keep_snapshot):
    _store, stored = stored_factory(
        gate_kind="technical_review",
        action_category="implementation",
        authority_reference=REFERENCE,
        source_expiry=now - timedelta(days=1),
    )
    pruned = replace(
        stored,
        detail_retained=False,
        projection=stored.projection
        if keep_snapshot
        else replace(stored.projection, snapshot=None),
    )
    row, html = local_page(pruned, now)
    assert row.local_details is None and row.presentation is None
    assert "PRIVATE" not in repr(asdict(row))
    assert "Source-reported request details" not in html
    assert "Authority reference (source/agent claim)" not in html
    for key in ("source_pointer", "quote", "scope", "exclusions", "supplied_lifetime"):
        assert REFERENCE[key] not in html
    assert (now - timedelta(days=1)).isoformat() not in html


@pytest.mark.parametrize("layout", ["friendly", "compact"])
@pytest.mark.parametrize("full_grant", [False, True])
def test_new_local_claims_never_enter_telegram_even_with_every_external_grant(
    stored_factory, now, layout, full_grant
):
    _store, stored = stored_factory(
        gate_kind="technical_review",
        action_category="installation",
        action="Opt-in action",
        authority_reference=REFERENCE,
        source_expiry=now - timedelta(days=1),
    )
    grant = frozenset(field.value for field in DisclosedField) if full_grant else frozenset()
    destination = DestinationIdentity(chat_id=123, bot_id=456)
    policy = CapturePolicy(
        policy_ref="synthetic-policy",
        settings_revision=0,
        destination_generation=1,
        channel_active=True,
        destination=destination,
        disclosure_fields=grant,
        created_at=now,
    )
    settings = Settings(
        destination_generation=1,
        channel_active=True,
        destination=destination,
        disclosure_fields=grant,
    )
    external = to_external_record(stored, now=now, policy=policy, settings=settings)
    direct = to_presentation_record(stored, now=now, allowed_fields=grant)
    assert {"gate_kind", "action_category", "authority_reference", "source_expiry"}.isdisjoint(
        type(external).model_fields
    )
    text = "\n".join(
        part.text for part in render_telegram_parts([external], layout, allowed_fields=grant)
    )
    for result in (external.model_dump_json(), direct.model_dump_json(), text):
        assert "technical_review" not in result and "installation" not in result
        assert (now - timedelta(days=1)).isoformat() not in result
        for key in ("source_pointer", "quote", "scope", "exclusions", "supplied_lifetime"):
            assert REFERENCE[key] not in result
    assert ("Opt-in action" in text) is full_grant


@pytest.mark.parametrize("layout", ["friendly", "compact"])
def test_mapped_claims_in_real_browser_remain_text_and_fit(
    stored_factory, now, layout, browser_page, live_ui, tmp_path
):
    authority = REFERENCE | {
        "source_pointer": "https://source.invalid/" + "P" * 180,
        "quote": "<script>window.claimExecuted=1</script>" + "Q" * 180,
    }
    _store, stored = stored_factory(
        gate_kind="technical_review",
        action_category="testing",
        authority_reference=authority,
        source_expiry=now - timedelta(days=1),
    )
    row = record_view(stored, now=now, allowed_fields=LOCAL_FIELDS, include_local_details=True)
    service, _app, origin = live_ui
    service.records = {row.short_reference: row}
    service.settings = revised_settings(service.settings, {"local_layout": layout})
    page = browser_page
    login(page, live_ui)
    measurements = []
    for width in (320, 390, 1280):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(origin + "/records/" + row.short_reference)
        claims = page.locator("#source-claims-title").locator("..")
        assert authority["quote"] in claims.inner_text()
        assert "not a verified identity" in claims.inner_text()
        assert "not an approval or executable policy" in claims.inner_text()
        assert claims.get_by_role("link").count() == 0
        assert page.evaluate("typeof window.claimExecuted") == "undefined"
        dimensions = page.evaluate("""() => ({
            viewport: innerWidth,
            document: document.documentElement.scrollWidth,
            body: document.body.scrollWidth,
            overflow: [...document.querySelectorAll('#source-claims-title ~ *')].some(el =>
                el.getBoundingClientRect().right > innerWidth + 1),
            clipped: [...document.querySelectorAll('html,body,main,section,dl,dd')].some(el =>
                ['hidden','clip'].includes(getComputedStyle(el).overflowX))
        })""")
        assert dimensions["document"] == dimensions["body"] == width
        assert not dimensions["overflow"] and not dimensions["clipped"]
        measurements.append({"layout": layout, **dimensions})
        if width == 390:
            page.screenshot(path=str(tmp_path / f"{layout}-source-claims.png"), full_page=True)
    (tmp_path / "measurements.json").write_text(
        json.dumps(measurements, indent=2) + "\n", encoding="utf-8"
    )
