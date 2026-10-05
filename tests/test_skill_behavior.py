"""Executable public skill examples, not a claim of live model/host qualification."""

import io
import json
from importlib.resources import files

from decision_mesh import cli
from decision_mesh.producer import ProducerDocument


def call(args, data=""):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(args, stdin=io.StringIO(data), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def example():
    raw = (
        files("decision_mesh")
        .joinpath("resources/decision-mesh/example-request.json")
        .read_text(encoding="utf-8")
    )
    ProducerDocument.model_validate_json(raw)
    return json.loads(raw)


def test_public_example_retries_preserve_allocation_without_starting_runtime(tmp_path):
    root = tmp_path / "configured"
    assert call(["producer", "enroll", "--data-dir", str(root)])[0] == 0
    document = example()
    first = call(["producer", "create", "--data-dir", str(root)], json.dumps(document))
    second = call(["producer", "create", "--data-dir", str(root)], json.dumps(document))
    assert first[0] == second[0] == 0
    a, b = json.loads(first[1]), json.loads(second[1])
    assert a["accepted_to_spool"] and not a["ingested"]
    assert a["event_id"] == b["event_id"] and a["revision"] == b["revision"]
    assert b["duplicate"]
    assert not (root / "runtime.json").exists()
    assert not (root / "decisionmesh.db").exists()


def test_example_changed_content_requires_new_operation_key(tmp_path):
    root = tmp_path / "configured"
    assert call(["producer", "enroll", "--data-dir", str(root)])[0] == 0
    doc = example()
    assert call(["producer", "create", "--data-dir", str(root)], json.dumps(doc))[0] == 0
    doc["snapshot"]["summary"] = "Updated harmless question"
    assert call(["producer", "update", "--data-dir", str(root)], json.dumps(doc))[0] == 1
    doc["idempotency_key"] = "example-task-output-format-update-2"
    code, output, errors = call(["producer", "update", "--data-dir", str(root)], json.dumps(doc))
    assert code == 0 and not errors and json.loads(output)["revision"] == 2


def test_example_does_not_implicitly_enroll_or_claim_host_authority(tmp_path):
    root = tmp_path / "unconfigured"
    doc = example()
    code, out, err = call(["producer", "create", "--data-dir", str(root)], json.dumps(doc))
    assert code == 1 and not out and "command_failed" in err
    assert not (root / "producer" / "enrollment.json").exists()
    assert call(["producer", "enroll", "--data-dir", str(root)])[0] == 0
    doc["snapshot"]["provenance"][0]["asserted_by"] = "host"
    code, out, err = call(["producer", "create", "--data-dir", str(root)], json.dumps(doc))
    assert code == 1 and not out and "command_failed" in err
    assert "Should this report" not in err
