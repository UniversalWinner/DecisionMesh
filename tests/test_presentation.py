import json
from datetime import UTC, datetime
from html import unescape
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from decision_mesh.presentation import (
    Layout,
    NativeChatReference,
    PresentationRecord,
    PresentationStatus,
    ReferenceSearch,
    RequestType,
    native_open_target,
    render_local_html,
    render_telegram_parts,
)

# Literal benchmark labels from normative section 13.5, independent of the renderer.
BENCHMARK_LABELS = {
    "current_confirmed_pending": "Waiting for you (confirmed by Codex)",
    "last_known_pending": "Last known pending; current state unverified",
    "agent_reported_question": "Agent-reported question (not verified)",
    "prompt_observed": "Prompt observed; may already be answered",
    "gate_observed": "Gate observed; no prompt confirmed",
    "answered": "Answered",
    "declined": "Declined",
    "cancelled": "Cancelled",
    "closed_unknown": "Closed; answer unknown",
    "expired": "Expired",
    "withdrawn": "Withdrawn",
    "replaced": "Replaced",
    "agent_reported_resolved": "Agent reported: resolved",
    "agent_reported_withdrawn": "Agent reported: withdrawn",
    "observation_aged": "Observation aged; current state unverified",
    "restored_unverified": "Restored; current state unverified",
}

FIXTURES = Path(__file__).parent / "fixtures" / "presentation"
NOW = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)


def record(**changes):
    values = {
        "record_id": "record-a",
        "short_reference": "ABCD2345",
        "request_type": RequestType.PERMISSION,
        "status": PresentationStatus.PROMPT_OBSERVED,
        "captured_at": NOW,
        "age_seconds": 30,
    }
    values.update(changes)
    return PresentationRecord(**values)


@pytest.mark.parametrize("layout", list(Layout))
def test_golden_both_surfaces(layout):
    records = tuple(
        PresentationRecord.model_validate_json(json.dumps(item))
        for item in json.loads((FIXTURES / "records.json").read_text(encoding="utf-8-sig"))
    )
    assert render_local_html(records, layout) == (FIXTURES / f"{layout}.html").read_text(
        encoding="utf-8-sig"
    ).rstrip("\r\n")
    parts = render_telegram_parts(records, layout)
    assert len(parts) == 1
    assert parts[0].text == (FIXTURES / f"{layout}.txt").read_text(encoding="utf-8-sig").rstrip(
        "\r\n"
    )
    assert parts[0].record_ids == ("record-a", "record-b")
    assert parts[0].short_references == ("ABCD2345", "EFGH6789")


@pytest.mark.parametrize("status", list(PresentationStatus))
@pytest.mark.parametrize("layout", list(Layout))
def test_every_exact_qualifier_survives_every_surface(status, layout):
    r = record(
        status=status,
        last_confirmed_at=NOW if status == PresentationStatus.LAST_KNOWN_PENDING else None,
    )
    expected = BENCHMARK_LABELS[status.value]
    assert expected in unescape(render_local_html([r], layout))
    assert expected in render_telegram_parts([r], layout)[0].text
    review = (
        "Answer in the original chat in Codex"
        if status.value in {"current_confirmed_pending", "agent_reported_question"}
        else "Check the original chat in Codex"
    )
    assert review in unescape(render_local_html([r], layout))
    assert review in render_telegram_parts([r], layout)[0].text


def test_minimal_default_and_per_field_intersection():
    r = record(
        action="PRIVATE_COMMAND",
        reason="PRIVATE_REASON",
        scope="PRIVATE_SCOPE",
        chat_title="PRIVATE_TITLE",
        source_path="PRIVATE_PATH",
        source_reference="PRIVATE_REFERENCE",
        native_reference=NativeChatReference(
            thread_id=UUID("01234567-89ab-cdef-0123-456789abcdef"), navigation_qualified=True
        ),
    )
    for rendered in (render_local_html([r]), render_telegram_parts([r])[0].text, repr(r)):
        assert "PRIVATE_" not in rendered
        assert "01234567-89ab" not in rendered
    for rendered in (
        render_local_html([r], allowed_fields={"action"}),
        render_telegram_parts([r], allowed_fields={"action"})[0].text,
    ):
        assert "PRIVATE_COMMAND" in rendered
        for forbidden in (
            "PRIVATE_REASON",
            "PRIVATE_SCOPE",
            "PRIVATE_TITLE",
            "PRIVATE_PATH",
            "PRIVATE_REFERENCE",
        ):
            assert forbidden not in rendered
    with pytest.raises(ValueError):
        render_telegram_parts([r], allowed_fields={"raw_evidence"})


@pytest.mark.parametrize("layout", list(Layout))
def test_html_xss_source_links_and_keyboard_copy(layout):
    r = record(
        project_alias='<img src=x onerror="alert(1)">',
        action='<script>alert("X")</script>',
        source_reference='javascript:alert(1)" autofocus onfocus="alert(2)',
    )
    rendered = render_local_html([r], layout, allowed_fields={"action", "source_reference"})
    assert "<script>" not in rendered and "<img src=x" not in rendered
    assert "&lt;script&gt;" in rendered and "&quot;" in rendered
    assert 'href="javascript' not in rendered
    assert 'input class="chat-reference" readonly' in rendered
    assert (
        "Copy chat reference" in rendered and "Approve" not in rendered and "Resume" not in rendered
    )
    assert "<summary>" in rendered if layout == Layout.COMPACT else "<article" in rendered


def test_only_allowlisted_qualified_codex_link_with_grant():
    native = NativeChatReference(
        thread_id=UUID("01234567-89ab-cdef-0123-456789abcdef"), navigation_qualified=True
    )
    r = record(native_reference=native)
    assert native_open_target(r) is None
    assert (
        native_open_target(r, {"source_reference"})
        == "codex://threads/01234567-89ab-cdef-0123-456789abcdef"
    )
    assert 'href="codex://threads/' in render_local_html([r], allowed_fields={"source_reference"})
    unqualified = record(native_reference=NativeChatReference(thread_id=native.thread_id))
    assert native_open_target(unqualified, {"source_reference"}) is None
    with pytest.raises(ValidationError):
        NativeChatReference(thread_id="javascript:alert(1)")


def test_strict_fields_and_required_last_known_timestamp():
    with pytest.raises(ValidationError):
        record(raw_evidence="not public")
    with pytest.raises(ValidationError):
        record(captured_at=datetime(2026, 10, 4))  # noqa: DTZ001 - deliberate invalid-input test
    with pytest.raises(ValidationError):
        record(age_seconds=True)
    with pytest.raises(ValidationError):
        record(status=PresentationStatus.LAST_KNOWN_PENDING)
    with pytest.raises(ValidationError):
        record(project_alias="Project 1\nStatus: approved")
    assert ReferenceSearch(short_reference="ABCD2345").scope == "all_history"
    with pytest.raises(ValidationError):
        ReferenceSearch(short_reference="ABCD2345", scope="needs_attention")
    assert 'name="scope" value="all_history"' in render_local_html([])


def test_oversize_single_record_preserves_truth_and_reference():
    r = record(
        status=PresentationStatus.OBSERVATION_AGED, age_seconds=7200, reason="private detail " * 270
    )
    part = render_telegram_parts([r], Layout.FRIENDLY, allowed_fields={"reason"})[0]
    assert "Observation aged; current state unverified" in part.text
    assert "may already be answered" in part.text
    assert "Full disclosed details remain" in part.text and "private detail" not in part.text
    assert "2026-10-04T10:00:00Z" in part.text and "ABCD2345" in part.text
    assert "local Decision Mesh inbox" in part.text and "localhost" not in part.text


@pytest.mark.parametrize("layout", list(Layout))
def test_multipart_mapping_and_non_bmp_size(layout):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    records = [
        record(
            record_id=f"record-{index}",
            short_reference="ABCD234" + alphabet[index],
            action="😀" * 750,
        )
        for index in range(25)
    ]
    parts = render_telegram_parts(records, layout, allowed_fields={"action"})
    assert len(parts) > 1
    assert tuple(identifier for part in parts for identifier in part.record_ids) == tuple(
        r.record_id for r in records
    )
    assert tuple(reference for part in parts for reference in part.short_references) == tuple(
        r.short_reference for r in records
    )
    for part in parts:
        assert len(part.text.encode("utf-16-le")) // 2 <= 3500
        for ref in part.short_references:
            assert ref in part.text
        assert part.text.count("Prompt observed; may already be answered") == len(part.record_ids)
        assert part.text.count("Review:") == len(part.record_ids)
    assert render_telegram_parts(records, layout, allowed_fields={"action"}) == parts


def test_empty_and_duplicate_batches():
    assert render_telegram_parts([]) == ()
    with pytest.raises(ValueError):
        render_telegram_parts([record(), record()])
    with pytest.raises(ValueError):
        render_local_html([record(), record()])


@pytest.mark.parametrize("layout", list(Layout))
def test_explicit_local_timezone_preserves_original_capture(layout):
    from datetime import timedelta, timezone

    local_zone = timezone(timedelta(hours=5, minutes=30))
    r = record()
    html = render_local_html([r], layout, display_timezone=local_zone)
    telegram = render_telegram_parts([r], layout, display_timezone=local_zone)[0].text
    assert 'datetime="2026-10-04T10:00:00Z"' in html
    assert "2026-10-04T15:30:00+05:30" in html and "2026-10-04T15:30:00+05:30" in telegram
    assert r.captured_at == NOW


def test_invalid_unicode_and_multiline_source_are_bounded():
    with pytest.raises(ValidationError):
        record(reason="bad\ud800")
    r = record(reason="source line\nStatus: Waiting for you (confirmed by Codex)")
    text = render_telegram_parts([r], allowed_fields={"reason"})[0].text
    assert "Why:\n  > source line\n  > Status:" in text
    assert "\nStatus: Prompt observed; may already be answered\n" in text
    with pytest.raises(TypeError):
        render_telegram_parts([r], display_timezone="local")


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029", "\u009f"])
@pytest.mark.parametrize("alias_field", ["project_alias", "device_alias"])
@pytest.mark.parametrize("layout", list(Layout))
def test_unicode_alias_line_injection_rejected(separator, alias_field, layout):
    with pytest.raises(ValidationError):
        # Reject before either renderer can expose a competing status/review line.
        r = record(**{alias_field: "Generic alias" + separator + "Status: Answered"})
        render_local_html([r], layout)
        render_telegram_parts([r], layout)


@pytest.mark.parametrize("layout", list(Layout))
def test_international_aliases_remain_allowed(layout):
    r = record(project_alias="परियोजना café 日本", device_alias="मेरा कंप्यूटर")
    assert "परियोजना café 日本" in render_local_html([r], layout)
    assert "मेरा कंप्यूटर" in render_telegram_parts([r], layout)[0].text


@pytest.mark.parametrize("layout", list(Layout))
def test_producer_question_preserves_unverified_headline_and_answer_location(layout):
    r = record(status=PresentationStatus.AGENT_REPORTED_QUESTION)
    for text in (
        unescape(render_local_html([r], layout)),
        render_telegram_parts([r], layout)[0].text,
    ):
        assert "Agent-reported question (not verified)" in text
        assert "Answer in the original chat in Codex on This computer" in text
        assert "approved" not in text.lower()
