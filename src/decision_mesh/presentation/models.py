"""Public presentation views: never a source of permission or lifecycle authority."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from unicodedata import category
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Layout(StrEnum):
    COMPACT = "compact"
    FRIENDLY = "friendly"


class RequestType(StrEnum):
    PERMISSION = "permission"
    QUESTION = "question"
    CHOICE = "choice"


class PresentationStatus(StrEnum):
    CURRENT_CONFIRMED_PENDING = "current_confirmed_pending"
    LAST_KNOWN_PENDING = "last_known_pending"
    AGENT_REPORTED_QUESTION = "agent_reported_question"
    PROMPT_OBSERVED = "prompt_observed"
    GATE_OBSERVED = "gate_observed"
    ANSWERED = "answered"
    DECLINED = "declined"
    CANCELLED = "cancelled"
    CLOSED_UNKNOWN = "closed_unknown"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    REPLACED = "replaced"
    AGENT_REPORTED_RESOLVED = "agent_reported_resolved"
    AGENT_REPORTED_WITHDRAWN = "agent_reported_withdrawn"
    OBSERVATION_AGED = "observation_aged"
    RESTORED_UNVERIFIED = "restored_unverified"


STATUS_LABELS = {
    PresentationStatus.CURRENT_CONFIRMED_PENDING: "Waiting for you (confirmed by Codex)",
    PresentationStatus.LAST_KNOWN_PENDING: "Last known pending; current state unverified",
    PresentationStatus.AGENT_REPORTED_QUESTION: "Agent-reported question (not verified)",
    PresentationStatus.PROMPT_OBSERVED: "Prompt observed; may already be answered",
    PresentationStatus.GATE_OBSERVED: "Gate observed; no prompt confirmed",
    PresentationStatus.ANSWERED: "Answered",
    PresentationStatus.DECLINED: "Declined",
    PresentationStatus.CANCELLED: "Cancelled",
    PresentationStatus.CLOSED_UNKNOWN: "Closed; answer unknown",
    PresentationStatus.EXPIRED: "Expired",
    PresentationStatus.WITHDRAWN: "Withdrawn",
    PresentationStatus.REPLACED: "Replaced",
    PresentationStatus.AGENT_REPORTED_RESOLVED: "Agent reported: resolved",
    PresentationStatus.AGENT_REPORTED_WITHDRAWN: "Agent reported: withdrawn",
    PresentationStatus.OBSERVATION_AGED: "Observation aged; current state unverified",
    PresentationStatus.RESTORED_UNVERIFIED: "Restored; current state unverified",
}


class DisclosedField(StrEnum):
    ACTION = "action"
    REASON = "reason"
    SCOPE = "scope"
    CHAT_TITLE = "chat_title"
    SOURCE_PATH = "source_path"
    SOURCE_REFERENCE = "source_reference"


class ViewModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, validate_default=True, hide_input_in_errors=True
    )


class NativeChatReference(ViewModel):
    """Qualification is supplied by the adapter, never inferred by the renderer."""

    thread_id: UUID
    navigation_qualified: bool = False


class PresentationRecord(ViewModel):
    record_id: str = Field(min_length=1, max_length=128)
    short_reference: str = Field(pattern=r"^[A-HJ-NP-Z2-9]{8}$")
    request_type: RequestType
    status: PresentationStatus
    captured_at: datetime
    age_seconds: int = Field(ge=0, le=3153600000)
    project_alias: str = Field(default="Project 1", min_length=1, max_length=80)
    device_alias: str = Field(default="This computer", min_length=1, max_length=80)
    last_confirmed_at: datetime | None = None
    native_reference: NativeChatReference | None = Field(default=None, repr=False)
    action: str | None = Field(default=None, max_length=2048, repr=False)
    reason: str | None = Field(default=None, max_length=4096, repr=False)
    scope: str | None = Field(default=None, max_length=4096, repr=False)
    chat_title: str | None = Field(default=None, max_length=160, repr=False)
    source_path: str | None = Field(default=None, max_length=2048, repr=False)
    source_reference: str | None = Field(default=None, max_length=1024, repr=False)

    @field_validator("captured_at", "last_confirmed_at")
    @classmethod
    def require_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("presentation timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator(
        "project_alias",
        "device_alias",
        "action",
        "reason",
        "scope",
        "chat_title",
        "source_path",
        "source_reference",
    )
    @classmethod
    def valid_unicode(cls, value: str | None) -> str | None:
        if value is not None and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("presentation text must be valid Unicode")
        return value

    @field_validator("project_alias", "device_alias")
    @classmethod
    def single_line_alias(cls, value: str) -> str:
        if any(category(char) in {"Cc", "Zl", "Zp"} for char in value):
            raise ValueError("aliases must be a single printable line")
        return value

    @model_validator(mode="after")
    def last_known_has_confirmation_time(self):
        if self.status == PresentationStatus.LAST_KNOWN_PENDING and self.last_confirmed_at is None:
            raise ValueError("last-known pending requires last-confirmed time")
        return self

    @property
    def evidence_label(self) -> str:
        return STATUS_LABELS[self.status]


class ReferenceSearch(ViewModel):
    """Input contract for a future all-history lookup; contains no storage behavior."""

    short_reference: str = Field(pattern=r"^[A-HJ-NP-Z2-9]{8}$")
    scope: Literal["all_history"] = "all_history"


class TelegramPart(ViewModel):
    text: str = Field(min_length=1, max_length=3500)
    record_ids: tuple[str, ...]
    short_references: tuple[str, ...]

    @model_validator(mode="after")
    def valid_membership(self):
        if not self.record_ids or len(self.record_ids) != len(self.short_references):
            raise ValueError("part membership must match its references")
        if len(set(self.record_ids)) != len(self.record_ids):
            raise ValueError("part contains repeated records")
        if len(self.text.encode("utf-16-le")) // 2 > 3500:
            raise ValueError("part exceeds the conservative Telegram length bound")
        return self
