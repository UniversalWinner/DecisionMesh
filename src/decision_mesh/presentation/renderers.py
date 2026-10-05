"""Deterministic escaped HTML and plain-text renderers over projected public data."""

from collections.abc import Iterable
from datetime import UTC, tzinfo
from html import escape

from .models import (
    DisclosedField,
    Layout,
    PresentationRecord,
    PresentationStatus,
    TelegramPart,
)

MAX_TELEGRAM_CHARS = 3500
OPTIONAL_LABELS = {
    DisclosedField.ACTION: "Task",
    DisclosedField.REASON: "Why",
    DisclosedField.SCOPE: "Scope",
    DisclosedField.CHAT_TITLE: "Chat",
    DisclosedField.SOURCE_PATH: "Source path",
    DisclosedField.SOURCE_REFERENCE: "Chat reference",
}


def _grant(fields: Iterable[DisclosedField | str]) -> frozenset[DisclosedField]:
    return frozenset(DisclosedField(field) for field in fields)


def _length(text: str) -> int:
    # Telegram limits entities in UTF-16 units; this is conservative for non-BMP text.
    return len(text.encode("utf-16-le")) // 2


def _time(value, display_timezone=UTC) -> str:
    return value.astimezone(display_timezone).isoformat(timespec="seconds").replace("+00:00", "Z")


def _age(seconds: int) -> str:
    return f"{seconds}s" if seconds < 60 else f"{seconds // 60}m"


def _review(record: PresentationRecord) -> str:
    if record.status in (
        PresentationStatus.CURRENT_CONFIRMED_PENDING,
        PresentationStatus.AGENT_REPORTED_QUESTION,
    ):
        lead = "Answer in the original chat in Codex"
    else:
        lead = "Check the original chat in Codex"
    return f"{lead} on {record.device_alias}; find {record.short_reference} in the local Decision Mesh inbox."


def _extra(record: PresentationRecord, grant: frozenset[DisclosedField]):
    for field, label in OPTIONAL_LABELS.items():
        value = getattr(record, field.value)
        if field in grant and value is not None:
            yield label, value


def native_open_target(record: PresentationRecord, allowed_fields=()) -> str | None:
    ref = record.native_reference
    if (
        ref
        and ref.navigation_qualified
        and DisclosedField.SOURCE_REFERENCE in _grant(allowed_fields)
    ):
        return f"codex://threads/{ref.thread_id}"
    return None


def _navigation(record: PresentationRecord, grant: frozenset[DisclosedField]) -> str:
    target = native_open_target(record, grant)
    if target:
        return f'<a class="native-open" href="{escape(target, quote=True)}">Open chat in Codex</a>'
    ref = record.short_reference
    if DisclosedField.SOURCE_REFERENCE in grant:
        ref = record.source_reference or (
            str(record.native_reference.thread_id) if record.native_reference else ref
        )
    # A readonly, labeled input supplies a working keyboard-copy fallback with no scripts.
    return (
        "<label>Copy chat reference "
        f'<input class="chat-reference" readonly value="{escape(ref, quote=True)}"></label>'
    )


def render_local_html(
    records: Iterable[PresentationRecord],
    layout=Layout.FRIENDLY,
    *,
    allowed_fields=(),
    display_timezone=UTC,
) -> str:
    if not isinstance(display_timezone, tzinfo):
        raise TypeError("display_timezone must be an explicit timezone")
    layout = Layout(layout)
    grant = _grant(allowed_fields)
    records = tuple(records)
    _unique(records)
    search = (
        '<form class="reference-search" method="get" action="/inbox">'
        '<input type="hidden" name="scope" value="all_history">'
        '<label for="reference-search">Find reference in all history</label>'
        '<input id="reference-search" name="short_reference" maxlength="8" '
        'pattern="[A-HJ-NP-Z2-9]{8}" required>'
        '<button type="submit">Find reference</button></form>'
    )
    body = []
    for record in records:
        ref = escape(record.short_reference)
        title = (
            f"{escape(record.request_type.value.title())} · {escape(record.project_alias)} · {ref}"
        )
        evidence = escape(record.evidence_label)
        timestamp = _time(record.captured_at)
        observed = f'<time datetime="{timestamp}">{_time(record.captured_at, display_timezone)}</time> · age {_age(record.age_seconds)}'
        confirmation = ""
        if record.last_confirmed_at is not None:
            confirmation = f'<p class="last-confirmed">Last confirmed at {_time(record.last_confirmed_at, display_timezone)}</p>'
        extra = "".join(
            f"<dt>{label}</dt><dd>{escape(value)}</dd>" for label, value in _extra(record, grant)
        )
        review = f'<p class="review">{escape(_review(record))}</p>'
        nav = _navigation(record, grant)
        if layout == Layout.COMPACT:
            action = (
                f'<span class="short-action">{escape(record.action)}</span>'
                if DisclosedField.ACTION in grant and record.action
                else ""
            )
            body.append(
                f'<li class="compact-row" id="ref-{ref}"><div class="row-main"><strong>{title}</strong>{action}'
                f'<span class="status">{evidence}</span><span class="observed">{observed}</span></div>'
                f"<details><summary>Details for {ref}</summary><dl>{extra}</dl>{confirmation}{review}{nav}</details></li>"
            )
        else:
            body.append(
                f'<article class="friendly-card" id="ref-{ref}"><h2>{title}</h2>'
                f"<dl><dt>Status</dt><dd>{evidence}</dd><dt>Observed</dt><dd>{observed}</dd>{extra}</dl>"
                f"{confirmation}{review}{nav}</article>"
            )
    container = (
        f'<ul class="compact-list">{"".join(body)}</ul>'
        if layout == Layout.COMPACT
        else f'<div class="friendly-cards">{"".join(body)}</div>'
    )
    return f'<section class="decision-mesh {layout.value}" aria-label="Decision Mesh inbox"><h1>Decision Mesh</h1>{search}{container}</section>'


def _unique(records):
    if len({r.record_id for r in records}) != len(records) or len(
        {r.short_reference for r in records}
    ) != len(records):
        raise ValueError("render batch contains repeated records or references")


def _telegram_record(record, layout, grant, display_timezone, *, minimal=False):
    lines = [
        f"Type: {record.request_type.value.title()}",
        f"Project: {record.project_alias}",
        f"Reference: {record.short_reference}",
        f"Observed: {_time(record.captured_at, display_timezone)} · age {_age(record.age_seconds)}",
        f"Status: {record.evidence_label}",
    ]
    if record.last_confirmed_at is not None:
        lines.append(f"Last confirmed at: {_time(record.last_confirmed_at, display_timezone)}")
    if record.status in (
        PresentationStatus.OBSERVATION_AGED,
        PresentationStatus.RESTORED_UNVERIFIED,
    ):
        lines.append(
            "Historical observation; may already be answered. No current outcome verified."
        )
    if minimal:
        lines.append("Full disclosed details remain in the local inbox.")
    else:
        for label, value in _extra(record, grant):
            source_lines = value.splitlines()
            if len(source_lines) > 1:
                lines.append(f"{label}:\n" + "\n".join(f"  > {line}" for line in source_lines))
            else:
                lines.append(f"{label}: {value}")
    lines.append(f"Review: {_review(record)}")
    return ("\n" if layout == Layout.COMPACT else "\n\n").join(lines)


def render_telegram_parts(
    records: Iterable[PresentationRecord],
    layout=Layout.COMPACT,
    *,
    allowed_fields=(),
    display_timezone=UTC,
) -> tuple[TelegramPart, ...]:
    if not isinstance(display_timezone, tzinfo):
        raise TypeError("display_timezone must be an explicit timezone")
    layout = Layout(layout)
    grant = _grant(allowed_fields)
    records = tuple(records)
    _unique(records)
    header = "Decision Mesh\n\n"
    separator = "\n\n---\n\n" if layout == Layout.FRIENDLY else "\n\n"
    parts, blocks, members = [], [], []

    def flush():
        if blocks:
            parts.append(
                TelegramPart(
                    text=header + separator.join(blocks),
                    record_ids=tuple(r.record_id for r in members),
                    short_references=tuple(r.short_reference for r in members),
                )
            )

    for record in records:
        block = _telegram_record(record, layout, grant, display_timezone)
        if _length(header + block) > MAX_TELEGRAM_CHARS:
            block = _telegram_record(record, layout, grant, display_timezone, minimal=True)
        if _length(header + separator.join([*blocks, block])) > MAX_TELEGRAM_CHARS:
            flush()
            blocks, members = [], []
        blocks.append(block)
        members.append(record)
    flush()
    return tuple(parts)
