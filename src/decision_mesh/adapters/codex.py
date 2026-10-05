"""Codex PermissionRequest observer: gate evidence only, no lifecycle guessing.

Importing this module and its CLI path uses only the standard library.
Runtime Pydantic imports are lazy and never used by the hook entry point.
"""

from __future__ import annotations

import sys
from typing import Any

from decision_mesh.capture import (
    MAX_EVENT_BYTES,
    CaptureError,
    ObserverArgumentParser,
    new_capture_metadata,
    parse_json,
    write_envelope,
)

ADAPTER_VERSION = "0.1.0a1"
OBSERVED_CLI_VERSION = "0.160.0"


def _id(value: Any, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
        raise CaptureError("invalid_hook_input")
    return value


def describe_capabilities(producer_id: str = "codex-permission-hook"):
    """Candidate normalization contract, not proof an installed hook runs."""
    from decision_mesh.contracts import SourceCapabilities

    return SourceCapabilities(
        producer_id=producer_id,
        producer_kind="native",
        allowed_event_kinds=("observation.recorded",),
        allowed_evidence_classes=("gate_observed",),
    )


def qualification_manifest() -> dict[str, Any]:
    return {
        "adapter": "codex-permission-hook",
        "adapter_version": ADAPTER_VERSION,
        "host": "codex",
        "surface": "windows-desktop",
        "target_cli_version": OBSERVED_CLI_VERSION,
        "supported_version_range": None,
        "qualification": "unverified",
        "documented_input": "PermissionRequest",
        "normalization_evidence": "gate_observed",
        "enabled_by_default": False,
        "actionable_native_notifications": False,
        "detection": "documented_not_measured",
        "exact_request_identity": False,
        "context": "documented_session_and_turn_only",
        "resolution": False,
        "execution_outcome": False,
        "native_navigation": False,
        "remote_response": False,
        "limitations": [
            "PermissionRequest precedes approval handling and does not prove prompt display.",
            "Documented PermissionRequest has no exact request/tool-use identity.",
            "Subagent hook session_id refers to the parent; identity cannot be inferred.",
            "No live Windows desktop hook/trust or non-deciding failure probe has passed.",
            "No matching by command text, event proximity, turn end, or PostToolUse.",
            "Native Windows capture candidate only; WSL capture unavailable.",
        ],
    }


def normalize_hook_dict(
    raw: bytes | str | dict[str, Any],
    *,
    metadata: dict[str, Any],
    producer_id: str = "codex-permission-hook",
    version: str | None = None,
    surface: str = "windows-desktop",
    retain_reason: bool = False,
    retain_action: bool = False,
) -> dict[str, Any]:
    """Allowlist documented fields. Payload IDs never elevate gate evidence."""
    value = parse_json(raw) if isinstance(raw, (bytes, str)) else raw
    if not isinstance(value, dict) or value.get("hook_event_name") != "PermissionRequest":
        raise CaptureError("unsupported_hook_event")
    session_id = _id(value.get("session_id"), required=True)
    turn_id = _id(value.get("turn_id"))
    tool_name = _id(value.get("tool_name"), required=True)
    _id(producer_id, required=True)
    _id(version)
    _id(surface, required=True)
    if not isinstance(value.get("cwd"), str) or not value["cwd"]:
        raise CaptureError("invalid_hook_input")
    tool_input = value.get("tool_input")
    # MCP inputs can be any JSON value. Never collect unrestricted arguments.
    reason = None
    action = None
    provenance = [
        {
            "field": "kind",
            "asserted_by": "host",
            "source_pointer": "hook_event_name:PermissionRequest",
        },
        {
            "field": "gate_kind",
            "asserted_by": "host",
            "source_pointer": "hook_event_name:PermissionRequest",
        },
    ]
    if isinstance(tool_input, dict):
        if retain_reason and tool_input.get("description") is not None:
            reason = tool_input["description"]
            if not isinstance(reason, str) or len(reason) > 4096:
                raise CaptureError("invalid_hook_input")
            provenance.append(
                {
                    "field": "reason",
                    "asserted_by": "host",
                    "source_pointer": "tool_input.description",
                }
            )
        if (
            retain_action
            and tool_name in {"Bash", "apply_patch"}
            and tool_input.get("command") is not None
        ):
            action = tool_input["command"]
            if not isinstance(action, str) or len(action) > 2048:
                raise CaptureError("invalid_hook_input")
            provenance.append(
                {"field": "action", "asserted_by": "host", "source_pointer": "tool_input.command"}
            )
    if set(metadata) != {"event_id", "captured_at", "capture_policy_ref"}:
        raise CaptureError("invalid_capture_metadata")
    return {
        "schema_version": 1,
        "producer_id": producer_id,
        **metadata,
        "occurred_at": None,
        "event_kind": "observation.recorded",
        "source_request_id": None,
        "revision": None,
        "source_context": {
            "producer_kind": "native",
            "host": "codex",
            "surface": surface,
            "version": version,
            "thread_id": None,
            "turn_id": turn_id,
            "session_id": session_id,
            "source_instance_id": None,
            "connection_epoch": None,
        },
        "evidence_class": "gate_observed",
        "payload": {
            "snapshot": {
                "kind": "permission",
                "gate_kind": "platform_permission",
                "action_category": "unknown",
                "title": "Codex permission gate observed",
                "summary": "Prompt display and the current outcome are unverified.",
                "task": None,
                "action": action,
                "scope": None,
                "exclusions": None,
                "reason": reason,
                "options": [],
                "source_expiry": None,
                "native_reference": None,
                "authority_reference": None,
                "provenance": provenance,
            },
            "authoritative_current": False,
            "continuity_restored": False,
        },
    }


def normalize_source_event(raw: bytes | str | dict[str, Any], **kwargs):
    from decision_mesh.contracts import validate_event

    return validate_event(normalize_hook_dict(raw, **kwargs))


def main(argv: list[str] | None = None) -> int:
    """Run only when deliberately configured/trusted; do not install or trust hooks."""
    parser = ObserverArgumentParser(add_help=False)
    parser.add_argument("--spool", required=True)
    parser.add_argument("--policy")
    parser.add_argument("--producer-id", default="codex-permission-hook")
    parser.add_argument("--host-version")
    args = None
    try:
        args = parser.parse_args(argv)
        raw = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
        envelope = normalize_hook_dict(
            raw,
            metadata=new_capture_metadata(args.policy),
            producer_id=args.producer_id,
            version=args.host_version,
        )
        write_envelope(args.spool, envelope)
    except (CaptureError, OSError, SystemExit) as error:
        code = error.code if isinstance(error, CaptureError) else "capture_unavailable"
        print(f"decision-mesh capture unavailable: {code}", file=sys.stderr)
        if args is not None:
            from pathlib import Path

            from decision_mesh.capture import _record_failure

            _record_failure(Path(args.spool), code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
