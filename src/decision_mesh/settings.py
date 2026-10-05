"""Validated local settings and immutable, credential-free capture grants."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from .contracts import utc_datetime


class SettingsError(ValueError):
    """A redacted settings failure; input bodies are never included."""


class SettingsConflict(SettingsError):
    """A settings write was based on an obsolete revision."""


class Layout(StrEnum):
    FRIENDLY = "friendly"
    COMPACT = "compact"


class DeliveryMode(StrEnum):
    IMMEDIATE = "immediate"
    DIGEST = "digest"


class DisclosureField(StrEnum):
    ACTION = "action"
    REASON = "reason"
    SCOPE = "scope"
    CHAT_TITLE = "chat_title"
    SOURCE_PATH = "source_path"
    SOURCE_REFERENCE = "source_reference"


Alias = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=80)]


class SettingsModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True
    )


class DestinationIdentity(SettingsModel):
    """The private recipient AND bot identity; never a token or display name."""

    provider: Literal["telegram"] = "telegram"
    chat_id: Annotated[StrictInt, Field(gt=0, le=2**63 - 1)]
    bot_id: Annotated[StrictInt, Field(gt=0, le=2**63 - 1)]


class Settings(SettingsModel):
    revision: Annotated[StrictInt, Field(ge=0)] = 0
    destination_generation: Annotated[StrictInt, Field(ge=0)] = 0
    local_layout: Layout = Layout.FRIENDLY
    telegram_layout: Layout = Layout.COMPACT
    delivery_mode: DeliveryMode = DeliveryMode.IMMEDIATE
    digest_interval_minutes: Annotated[StrictInt, Field(ge=1, le=1440)] = 10
    global_pause: StrictBool = False
    provider_suspended: StrictBool = False
    channel_active: StrictBool = False
    destination: DestinationIdentity | None = None
    disclosure_fields: frozenset[DisclosureField] = frozenset()
    device_alias: Alias = "This computer"
    autostart: StrictBool = False
    retention_days: Annotated[StrictInt, Field(ge=1, le=365)] = 30

    @field_validator("device_alias")
    @classmethod
    def printable_alias(cls, value: str) -> str:
        return validate_alias(value)

    @model_validator(mode="after")
    def activated_destination(self):
        if self.channel_active and self.destination is None:
            raise ValueError("active channel requires a private destination")
        return self


class CapturePolicy(SettingsModel):
    policy_ref: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    settings_revision: Annotated[StrictInt, Field(ge=0)]
    destination_generation: Annotated[StrictInt, Field(ge=0)]
    channel_active: StrictBool
    destination: DestinationIdentity | None
    disclosure_fields: frozenset[DisclosureField] = frozenset()
    created_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def aware_timestamp(cls, value):
        return utc_datetime(value)

    @model_validator(mode="after")
    def activated_destination(self):
        if self.channel_active and self.destination is None:
            raise ValueError("active capture policy requires a destination")
        return self

    def permits_route(self, current: Settings) -> bool:
        return bool(
            self.channel_active
            and current.channel_active
            and self.destination is not None
            and self.destination == current.destination
            and self.destination_generation == current.destination_generation
        )

    def effective_fields(self, current: Settings) -> frozenset[DisclosureField]:
        if not self.permits_route(current):
            return frozenset()
        return self.disclosure_fields & current.disclosure_fields


def validate_alias(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 80
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise SettingsError("invalid_alias")
    return value


def revised_settings(current: Settings, changes: dict) -> Settings:
    """Validate a complete candidate; protected counters cannot be caller-selected."""
    if not isinstance(changes, dict) or {"revision", "destination_generation"} & changes.keys():
        raise SettingsError("protected_settings_field")
    try:
        values = current.model_dump(mode="python") | changes
        candidate = Settings.model_validate(values)
        changed_route = (
            candidate.destination != current.destination
            or candidate.channel_active != current.channel_active
        )
        return Settings.model_validate(
            candidate.model_dump(mode="python")
            | {
                "revision": current.revision + 1,
                "destination_generation": current.destination_generation + int(changed_route),
            }
        )
    except (ValueError, TypeError, OverflowError):
        raise SettingsError("invalid_settings") from None
