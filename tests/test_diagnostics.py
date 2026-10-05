import json

import pytest

from decision_mesh.capture import atomic_write_owner_only, ensure_spool_dir
from decision_mesh.diagnostics import RuntimeCounters, doctor, export_report
from decision_mesh.producer import ExplicitProducer, enroll_producer
from decision_mesh.runtime import Runtime
from decision_mesh.runtime_control import RuntimePaths


def test_absent_is_distinct_from_failed_and_no_runtime_starts(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    report = doctor(paths)
    assert report["runtime"] == "absent"
    assert report["storage"]["status"] == "absent"
    assert report["secret_backend"] == "not_checked"
    assert report["native_support"] == "unverified"
    assert not paths.root.exists()
    ensure_spool_dir(paths.root)
    atomic_write_owner_only(paths.database, b"not a database")
    assert doctor(paths)["storage"]["status"] == "failed"


def test_real_store_report_is_redacted_and_read_only(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    enroll_producer(paths.producer)
    ExplicitProducer(paths.producer).create(
        {
            "source_request_id": "PRIVATE_ID",
            "snapshot": {
                "kind": "question",
                "title": "PRIVATE_PAYLOAD",
                "summary": "PRIVATE_SECRET",
            },
        }
    )
    with Runtime(paths.root, local_only=True) as runtime:
        before = runtime.store.list_records()[0]
        report = doctor(paths, probe=lambda *_args: None)
        assert report["storage"]["integrity_ok"] is True
        assert report["storage"]["source_count"] == 1
        assert report["storage"]["last_capture_at"]
        assert runtime.store.list_records()[0] == before
        raw = json.dumps(report)
        assert all(
            value not in raw
            for value in (
                "PRIVATE_ID",
                "PRIVATE_PAYLOAD",
                "PRIVATE_SECRET",
                runtime.metadata.control_secret,
                runtime.metadata.instance_id,
                str(paths.root),
            )
        )
        export = ensure_spool_dir(tmp_path / "exports") / "redacted.json"
        export_report(report, export)
        assert json.loads(export.read_bytes()) == report
        with pytest.raises(ValueError):
            export_report(report, export)


def test_counters_are_allowlisted_and_capture_failure_is_actual_marker(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    counters = RuntimeCounters(paths.root / "runtime-diagnostics.json")
    counters.bump("scan_failed")
    with pytest.raises(ValueError):
        counters.bump("SECRET")
    spool = paths.producer / "spool"
    ensure_spool_dir(spool)
    atomic_write_owner_only(
        spool / ".capture-failure",
        b'{"code":"spool_capacity","lost_count_lower_bound":1,"secret":"NEVER_EXPORT"}',
    )
    report = doctor(paths)
    assert report["runtime_counters"]["counts"] == {"scan_failed": 1}
    assert report["capture_counters"]["lost_count_lower_bound"] == 1
    assert "NEVER_EXPORT" not in json.dumps(report)


def test_corrupt_metadata_is_not_reported_as_readiness(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    ensure_spool_dir(paths.root)
    from decision_mesh.capture import owner_file_lock

    atomic_write_owner_only(paths.metadata, b'{"token":"PRIVATE_SECRET"}')
    with owner_file_lock(paths.lock, timeout=0):
        result = doctor(paths)
    assert result["runtime"] == "authentication_or_metadata_failed"
    assert "PRIVATE_SECRET" not in json.dumps(result)


def test_rt1_doctor_reads_persisted_local_verification_without_rechecking(tmp_path):
    paths = RuntimePaths(tmp_path / "data")
    with Runtime(paths.root, local_only=True) as runtime:
        assert runtime.service.verify_local()["ok"]
        evidence = paths.root / "setup.json"
        before = evidence.read_bytes()
        runtime.service.verify_capture = lambda: (_ for _ in ()).throw(
            AssertionError("read mutated")
        )
        report = doctor(paths, probe=lambda *_args: None)
        assert report["verification_scope"] == "local_runtime"
        assert report["environment_verified"] and report["local_capture_verified"]
        assert report["native_support"] == "unverified"
        assert evidence.read_bytes() == before
        assert "environment_signature" not in json.dumps(report)


@pytest.mark.parametrize("available", [True, False])
def test_rt4_doctor_uses_same_verified_installation_resolver(tmp_path, monkeypatch, available):
    from decision_mesh import diagnostics
    from decision_mesh.runtime_control import RuntimeErrorCode

    executable = tmp_path / "decisionmesh.exe"
    executable.write_bytes(b"resolver fixture")
    calls = []

    def resolve():
        calls.append(True)
        if not available:
            raise RuntimeErrorCode("installed_command_unavailable")
        return executable

    monkeypatch.setattr(diagnostics, "resolve_installed_console", resolve)
    paths = RuntimePaths(tmp_path / "data")
    report = doctor(paths)
    assert report["installed_command"] == ("available" if available else "missing_or_stale")
    assert calls == [True] and not paths.root.exists()
    assert str(executable) not in json.dumps(report)
