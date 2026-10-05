import json
import subprocess
import sys
from pathlib import Path

import pytest

from decision_mesh.adapters import codex
from decision_mesh.capture import CaptureError
from decision_mesh.contracts import EvidenceClass, canonical_event_bytes

META = {
    "event_id": "test-gate-1",
    "captured_at": "2026-10-04T00:00:00Z",
    "capture_policy_ref": None,
}


def hook():
    return {
        "session_id": "synthetic-session",
        "turn_id": "synthetic-turn",
        "cwd": "C:/SyntheticProject",
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "echo PRIVATE_SECRET", "description": "PRIVATE_REASON"},
        "transcript_path": "C:/PRIVATE_TRANSCRIPT",
        "model": "model-name",
    }


def test_gate_never_becomes_prompt_or_pending_or_execution():
    value = hook()
    value.update(request_id="invented", tool_use_id="invented", decision="allow")
    event = codex.normalize_source_event(value, metadata=META, version="0.160.0")
    assert event.event_kind == "observation.recorded"
    assert event.evidence_class == EvidenceClass.GATE_OBSERVED
    assert event.source_request_id is None and event.revision is None
    assert not event.payload.authoritative_current and not event.payload.continuity_restored
    assert event.payload.snapshot.native_reference is None
    assert event.source_context.session_id == "synthetic-session"
    assert event.source_context.thread_id is None


def test_unrestricted_tool_payload_private_paths_and_reason_not_collected_by_default():
    event = codex.normalize_source_event(hook(), metadata=META)
    encoded = canonical_event_bytes(event)
    assert b"PRIVATE" not in encoded and b"C:/SyntheticProject" not in encoded
    assert event.payload.snapshot.action is None and event.payload.snapshot.reason is None


def test_explicit_allowlisted_details_have_field_provenance():
    event = codex.normalize_source_event(
        hook(), metadata=META, retain_reason=True, retain_action=True
    )
    assert event.payload.snapshot.action == "echo PRIVATE_SECRET"
    assert event.payload.snapshot.reason == "PRIVATE_REASON"
    assert {p.field for p in event.payload.snapshot.provenance} >= {"action", "reason"}


@pytest.mark.parametrize("tool", ["apply_patch", "mcp__synthetic__read"])
def test_documented_file_mcp_stay_gate_only(tool):
    value = hook()
    value["tool_name"] = tool
    value["tool_input"] = {"sensitive": "PRIVATE_SECRET"}
    event = codex.normalize_source_event(value, metadata=META, retain_action=True)
    assert event.evidence_class == EvidenceClass.GATE_OBSERVED
    assert event.payload.snapshot.action is None


@pytest.mark.parametrize(
    "name", ["PreToolUse", "PostToolUse", "Stop", "Interrupt", "UserPromptSubmit", "Notification"]
)
def test_other_events_cannot_fabricate_prompt_closure_or_native_question(name):
    value = hook()
    value["hook_event_name"] = name
    with pytest.raises(CaptureError, match="unsupported_hook_event"):
        codex.normalize_source_event(value, metadata=META)


def test_identical_commands_are_distinct_observations_not_authority_merge():
    first = codex.normalize_source_event(hook(), metadata=META)
    second = codex.normalize_source_event(hook(), metadata={**META, "event_id": "test-gate-2"})
    assert first.event_id != second.event_id
    assert first.source_request_id is second.source_request_id is None


def test_manifest_is_honestly_unqualified_nonactionable():
    manifest = codex.qualification_manifest()
    assert manifest["qualification"] == "unverified"
    assert not manifest["enabled_by_default"]
    assert not manifest["actionable_native_notifications"]
    caps = codex.describe_capabilities()
    assert not caps.authoritative_lifecycle and not caps.continuous_stream
    assert not caps.one_to_one_execution and caps.identity_scope == ()


def test_codex_hook_cli_no_decision_stdout_and_real_spool(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "decision_mesh.adapters.codex",
            "--spool",
            str(tmp_path / "spool"),
            "--host-version",
            "0.160.0",
        ],
        input=json.dumps(hook()).encode(),
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0 and result.stdout == result.stderr == b""
    paths = list((tmp_path / "spool").glob("*.json"))
    assert len(paths) == 1
    assert json.loads(paths[0].read_bytes())["evidence_class"] == "gate_observed"


def test_synthetic_fixture_is_explicitly_synthetic():
    fixture = Path(__file__).parent / "fixtures/codex/permission_request.synthetic.json"
    assert json.loads(fixture.read_text())["session_id"] == "synthetic-session"
