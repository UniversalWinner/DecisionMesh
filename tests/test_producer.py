"""Producer durability tests; synthetic documents do not qualify native hosts."""

import json
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta

import pytest

import decision_mesh.producer as producer_module
from decision_mesh.capture import (
    CaptureError,
    assert_owner_only,
    atomic_write_owner_only,
    ensure_spool_dir,
)
from decision_mesh.contracts import validate_event
from decision_mesh.producer import (
    ExplicitProducer,
    ProducerDocument,
    ProducerError,
    enroll_producer,
)


def document(**changes):
    value = {
        "source_request_id": "request-one",
        "snapshot": {"kind": "question", "title": "Pick a target", "summary": "A or B?"},
    }
    value.update(changes)
    return value


@pytest.fixture
def producer(tmp_path, now):
    root = tmp_path / "producer"
    enroll_producer(root)
    return ExplicitProducer(root, clock=lambda: now)


def policy(path, reference, active=True):
    atomic_write_owner_only(
        path,
        json.dumps(
            {"schema_version": 1, "capture_policy_ref": reference, "channel_active": active}
        ).encode(),
    )


def test_controlled_enrollment_is_stable_and_unique(tmp_path):
    first = enroll_producer(tmp_path / "one")
    assert enroll_producer(tmp_path / "one") == first
    assert enroll_producer(tmp_path / "two").producer_id != first.producer_id
    assert first.producer_id.startswith("explicit:")
    assert first.capabilities.producer_kind == "explicit"
    assert not first.capabilities.authoritative_lifecycle


def test_producer_requires_enrollment_and_rejects_native_enrollment(tmp_path):
    with pytest.raises(ProducerError, match="producer_not_enrolled"):
        ExplicitProducer(tmp_path / "absent")
    root = tmp_path / "one"
    enroll_producer(root)
    atomic_write_owner_only(
        root / "enrollment.json", b'{"schema_version":1,"producer_id":"codex-native"}'
    )
    with pytest.raises(ProducerError, match="invalid_enrollment"):
        ExplicitProducer(root)


@pytest.mark.parametrize("suffix", ["producer", "missing/producer", "missing/deep/producer"])
def test_constructor_rejects_missing_enrollment_without_creating_parents(tmp_path, suffix):
    with pytest.raises(ProducerError, match="^producer_not_enrolled$"):
        ExplicitProducer(tmp_path / suffix)
    assert list(tmp_path.iterdir()) == []


def test_constructor_rejects_existing_unenrolled_directory_without_writes(tmp_path):
    root = ensure_spool_dir(tmp_path / "producer")
    with pytest.raises(ProducerError, match="^producer_not_enrolled$"):
        ExplicitProducer(root)
    assert list(root.iterdir()) == []
    assert_owner_only(root)


def test_constructor_does_not_adopt_unprotected_existing_directory(tmp_path):
    root = tmp_path / "producer"
    root.mkdir()
    if sys.platform != "win32":
        root.chmod(0o755)
    with pytest.raises(CaptureError):
        assert_owner_only(root)
    with pytest.raises(ProducerError, match="^producer_unavailable$"):
        ExplicitProducer(root)
    with pytest.raises(CaptureError):
        assert_owner_only(root)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "contents",
    [
        b'{"schema_version":1,"producer_id":"codex-native"}',
        b'{"schema_version":1,"producer_id":"other-producer"}',
        b'{"producer_id":"synthetic-enrollment-secret-do-not-log"',
    ],
    ids=["native-namespace", "foreign-namespace", "malformed-json"],
)
def test_constructor_rejects_invalid_enrollment_without_writes(tmp_path, contents, capsys):
    root = ensure_spool_dir(tmp_path / "producer")
    atomic_write_owner_only(root / "enrollment.json", contents)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(ProducerError, match="^invalid_enrollment$") as caught:
        ExplicitProducer(root)
    assert caught.value.args == ("invalid_enrollment",)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
    assert capsys.readouterr() == ("", "")


def test_constructor_does_not_adopt_unprotected_enrollment(tmp_path):
    root = ensure_spool_dir(tmp_path / "producer")
    path = root / "enrollment.json"
    contents = b'{"schema_version":1,"producer_id":"explicit:11111111111111111111111111111111"}'
    path.write_bytes(contents)
    if sys.platform != "win32":
        path.chmod(0o644)
    with pytest.raises(CaptureError):
        assert_owner_only(path)
    with pytest.raises(ProducerError, match="^invalid_enrollment$"):
        ExplicitProducer(root)
    with pytest.raises(CaptureError):
        assert_owner_only(path)
    assert list(root.iterdir()) == [path]
    assert path.read_bytes() == contents


@pytest.mark.parametrize("existing_directory", [False, True], ids=["missing", "existing"])
def test_explicit_setup_after_rejected_constructor_preserves_retry(
    tmp_path, now, existing_directory
):
    data_root = tmp_path / "app"
    root = data_root / "producer"
    if existing_directory:
        ensure_spool_dir(data_root)
        ensure_spool_dir(root)
    with pytest.raises(ProducerError, match="^producer_not_enrolled$"):
        ExplicitProducer(root)
    ensure_spool_dir(data_root)
    enrollment = enroll_producer(root)
    enrollment_bytes = (root / "enrollment.json").read_bytes()
    original = ExplicitProducer(root, clock=lambda: now)
    first = original.create(document(idempotency_key="after-explicit-setup"))
    spool_bytes = first.path.read_bytes()
    retry = ExplicitProducer(root, clock=lambda: now + timedelta(minutes=10)).create(
        document(idempotency_key="after-explicit-setup")
    )
    assert first.producer_id == enrollment.producer_id
    assert first.revision == 1 and first.captured_at == now
    assert first.capture_policy_ref is None
    assert first.accepted_to_spool and not first.ingested
    assert retry.duplicate and replace(retry, duplicate=False) == first
    assert retry.path.read_bytes() == spool_bytes
    assert enroll_producer(root) == enrollment
    assert (root / "enrollment.json").read_bytes() == enrollment_bytes
    for path in (data_root, root, original.journal_dir, original.spool_dir, first.path):
        assert_owner_only(path)


def test_full_lifecycle_is_reported_only_and_runtime_absent(producer):
    receipts = [
        getattr(producer, method)(document())
        for method in ("create", "update", "resolve", "withdraw")
    ]
    assert [r.revision for r in receipts] == [1, 2, 3, 4]
    for receipt in receipts:
        event = validate_event(receipt.path.read_bytes())
        assert event.evidence_class == "producer_reported"
        assert event.source_context.producer_kind == "explicit"
        assert not event.payload.authoritative_current
        assert receipt.accepted_to_spool and not receipt.ingested
    assert validate_event(receipts[2].path.read_bytes()).payload.outcome == "resolved"
    assert validate_event(receipts[3].path.read_bytes()).payload.outcome == "withdrawn"
    assert not list(producer.data_dir.rglob("*.sqlite*"))


@pytest.mark.parametrize(
    "extra",
    [
        {"producer_id": "codex-native"},
        {"producer_id": "other-producer"},
        {"revision": 900},
        {"evidence_class": "source_authoritative"},
        {"capture_policy_ref": "privileged-grant"},
        {"source_context": {"producer_kind": "native"}},
        {
            "snapshot": {
                "kind": "question",
                "provenance": [{"field": "title", "asserted_by": "host"}],
            }
        },
        {
            "snapshot": {
                "kind": "question",
                "authority_reference": {"quote": "secret", "asserted_by": "host"},
            }
        },
    ],
)
def test_no_foreign_namespace_or_host_claims(producer, extra):
    with pytest.raises(ProducerError, match="invalid_producer_document"):
        producer.resolve(document(**extra))
    assert not list(producer.spool_dir.glob("*.json"))


def test_constructed_model_is_revalidated(producer):
    forged = ProducerDocument.model_construct(
        source_request_id="x",
        snapshot={"kind": "wrong"},
        source_context={"producer_kind": "native"},
    )
    with pytest.raises(ProducerError, match="invalid_producer_document"):
        producer.create(forged)


def test_same_key_rejects_changed_body_and_operation(producer):
    original = producer.create(document(idempotency_key="retry-secret"))
    with pytest.raises(ProducerError, match="idempotency_conflict"):
        producer.create(
            document(
                idempotency_key="retry-secret", snapshot={"kind": "question", "title": "Different"}
            )
        )
    with pytest.raises(ProducerError, match="idempotency_conflict"):
        producer.resolve(document(idempotency_key="retry-secret"))
    assert producer.create(document(idempotency_key="retry-secret")).event_id == original.event_id


def test_retry_after_later_operation_retains_original_identity(producer):
    first = producer.create(document(idempotency_key="first"))
    producer.update(document(idempotency_key="later"))
    retry = producer.create(document(idempotency_key="first"))
    assert replace(retry, duplicate=False) == first
    assert retry.duplicate
    assert (
        producer.create(document(idempotency_key=first.idempotency_key)).event_id == first.event_id
    )


def test_latest_no_key_reuses_only_latest_identical_operation(producer):
    first = producer.create(document())
    assert producer.create(document()).event_id == first.event_id
    producer.update(document())
    second = producer.create(document())
    assert second.revision == 3 and second.event_id != first.event_id
    assert (
        producer.create(document(idempotency_key=first.idempotency_key)).event_id == first.event_id
    )


def test_distinct_request_ids_never_content_merge(producer):
    first = producer.create(document())
    second = producer.create(document(source_request_id="request-two"))
    assert first.event_id != second.event_id
    assert first.revision == second.revision == 1


def test_allocation_persisted_before_publish_failure(producer, monkeypatch):
    real_write = producer_module.write_envelope
    monkeypatch.setattr(
        producer_module,
        "write_envelope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CaptureError("disk_full")),
    )
    with pytest.raises(ProducerError, match="producer_spool_unavailable"):
        producer.create(document(idempotency_key="durable"))
    journal = json.loads(next(producer.journal_dir.glob("*.json")).read_text())
    assert journal["max_revision"] == 1
    assert not list(producer.spool_dir.glob("*.json"))
    monkeypatch.setattr(producer_module, "write_envelope", real_write)
    fresh = ExplicitProducer(producer.data_dir)
    receipt = fresh.create(document(idempotency_key="durable"))
    assert receipt.event_id == journal["receipts"][0]["event_id"] and receipt.revision == 1
    assert receipt.duplicate


def test_real_process_crash_after_allocation_has_stable_retry(producer, now):
    code = """
import os, sys
import decision_mesh.producer as module
from decision_mesh.producer import ExplicitProducer
from datetime import datetime
module.write_envelope = lambda *args, **kwargs: os._exit(73)
ExplicitProducer(sys.argv[1], clock=lambda: datetime.fromisoformat(sys.argv[2])).create({
    'source_request_id': 'crash-request',
    'snapshot': {'kind': 'question', 'title': 'Survives restart'},
    'idempotency_key': 'crash-key',
})
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(producer.data_dir), now.isoformat()],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 73, result.stderr.decode()
    assert not list(producer.spool_dir.glob("*.json"))
    journal = json.loads(next(producer.journal_dir.glob("*.json")).read_text())
    fresh = ExplicitProducer(producer.data_dir, clock=lambda: now + timedelta(hours=4))
    receipt = fresh.create(
        document(
            source_request_id="crash-request",
            snapshot={"kind": "question", "title": "Survives restart"},
            idempotency_key="crash-key",
        )
    )
    assert receipt.event_id == journal["receipts"][0]["event_id"]
    assert receipt.captured_at == now and receipt.revision == 1


def test_parallel_processes_allocate_monotonic_distinct_revisions(producer):
    code = """
import json, sys
from decision_mesh.producer import ExplicitProducer
receipt = ExplicitProducer(sys.argv[1]).update({'source_request_id': 'parallel', 'snapshot': {'kind': 'question', 'title': sys.argv[2]}, 'idempotency_key': sys.argv[2]})
print(json.dumps({'revision': receipt.revision, 'event_id': receipt.event_id}))
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(producer.data_dir), str(i)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(6)
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr.decode()
        results.append(json.loads(stdout))
    assert sorted(r["revision"] for r in results) == list(range(1, 7))
    assert len({r["event_id"] for r in results}) == 6


def test_original_policy_and_capture_time_survive_disable_reenable_retry(producer, now):
    path = producer.data_dir / "policy.json"
    policy(path, "generation-1")
    current = ExplicitProducer(producer.data_dir, policy_path=path, clock=lambda: now)
    first = current.create(document(idempotency_key="stable"))
    original = first.path.read_bytes()
    policy(path, "generation-1", active=False)
    local = current.update(document(idempotency_key="disabled"))
    assert local.capture_policy_ref is None
    policy(path, "generation-3")
    later = ExplicitProducer(
        producer.data_dir, policy_path=path, clock=lambda: now + timedelta(hours=2)
    )
    retry = later.create(document(idempotency_key="stable"))
    assert retry.capture_policy_ref == "generation-1"
    assert retry.captured_at == now and retry.path.read_bytes() == original
    assert later.update(document(idempotency_key="disabled")).capture_policy_ref is None
    assert later.update(document(idempotency_key="fresh")).capture_policy_ref == "generation-3"


@pytest.mark.parametrize(
    "contents",
    [
        None,
        b"not-json",
        b'{"schema_version":1,"channel_active":true}',
        b'{"schema_version":1,"capture_policy_ref":"x","channel_active":false}',
    ],
)
def test_missing_or_invalid_current_policy_is_local_only(producer, contents):
    path = producer.data_dir / "policy.json"
    if contents is not None:
        atomic_write_owner_only(path, contents)
    current = ExplicitProducer(producer.data_dir, policy_path=path)
    assert current.create(document()).capture_policy_ref is None
    policy(path, "new-grant")
    assert current.create(document()).capture_policy_ref is None


def test_receipt_and_byte_capacity_never_evict_old_identities(producer):
    bounded = ExplicitProducer(producer.data_dir, max_receipts_per_request=2)
    first = bounded.create(document(idempotency_key="first"))
    bounded.update(document(idempotency_key="second"))
    with pytest.raises(ProducerError, match="allocation_capacity"):
        bounded.update(document(idempotency_key="third"))
    assert bounded.create(document(idempotency_key="first")).event_id == first.event_id
    bounded_bytes = ExplicitProducer(producer.data_dir, max_journal_bytes=1024)
    for index in range(20):
        try:
            bounded_bytes.create(
                document(source_request_id="bounded-bytes", idempotency_key=str(index))
            )
        except ProducerError as error:
            assert error.code == "allocation_capacity"
            break
    else:
        pytest.fail("byte limit did not apply")
    assert all(path.stat().st_size <= 1024 for path in producer.journal_dir.glob("*.json"))


def test_compact_journal_and_errors_never_contain_payload_or_key(producer, capsys):
    secret = "synthetic-secret-do-not-log"
    producer.create(
        document(
            source_request_id=secret,
            snapshot={"kind": "question", "title": secret},
            idempotency_key=secret,
        )
    )
    raw = next(producer.journal_dir.glob("*.json")).read_text()
    assert secret not in raw
    assert "payload_digest" in raw and "snapshot" not in raw
    with pytest.raises(ProducerError) as caught:
        producer.resolve(document(source_request_id=secret, idempotency_key=secret))
    assert secret not in str(caught.value)
    assert capsys.readouterr() == ("", "")


def test_corrupt_allocation_journal_fails_closed(producer):
    producer.create(document())
    journal = next(producer.journal_dir.glob("*.json"))
    atomic_write_owner_only(journal, b'{"max_revision":0,"secret":"do-not-log"}')
    with pytest.raises(ProducerError, match="invalid_allocation_journal"):
        producer.update(document())
    assert len(list(producer.spool_dir.glob("*.json"))) == 1


def test_failed_journal_commit_never_publishes_or_consumes_revision(producer, monkeypatch):
    original = producer_module.atomic_write_owner_only

    def fail(*args, **kwargs):
        raise CaptureError("disk_full")

    monkeypatch.setattr(producer_module, "atomic_write_owner_only", fail)
    with pytest.raises(ProducerError):
        producer.create(document(idempotency_key="before-commit"))
    assert not list(producer.spool_dir.glob("*.json"))
    assert not list(producer.journal_dir.glob("*.json"))
    monkeypatch.setattr(producer_module, "atomic_write_owner_only", original)
    assert producer.create(document(idempotency_key="before-commit")).revision == 1


def test_allocated_gap_and_later_retry_keep_the_original_envelope(producer, monkeypatch, now):
    real_write = producer_module.write_envelope
    monkeypatch.setattr(
        producer_module,
        "write_envelope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CaptureError("unavailable")),
    )
    with pytest.raises(ProducerError):
        producer.create(document(idempotency_key="opening"))
    monkeypatch.setattr(producer_module, "write_envelope", real_write)
    later = producer.resolve(document(idempotency_key="closing"))
    assert later.revision == 2
    original = producer.create(document(idempotency_key="opening"))
    assert original.revision == 1 and original.captured_at == now
    assert original.duplicate


@pytest.mark.parametrize("as_model", [False, True], ids=["mapping", "document-model"])
@pytest.mark.parametrize("forged_field", ["snapshot", "source_context", "nested_provenance"])
def test_nested_forged_models_fail_before_allocation_without_disclosure(
    producer, as_model, forged_field, capsys, caplog
):
    import traceback
    import warnings

    from decision_mesh.contracts import DecisionSnapshot, Provenance, SourceContext

    secret = "synthetic-secret-do-not-log"
    values = document()
    if forged_field == "snapshot":
        values["snapshot"] = DecisionSnapshot.model_construct(kind=secret)
    elif forged_field == "source_context":
        values["source_context"] = SourceContext.model_construct(
            producer_kind="explicit", host={"sensitive": secret}
        )
    else:
        values["snapshot"] = {
            "kind": "question",
            "provenance": (Provenance.model_construct(field=secret, asserted_by="agent"),),
        }
    value = ProducerDocument.model_construct(**values) if as_model else values
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        with pytest.raises(ProducerError) as caught:
            producer.create(value)
    assert caught.value.code == "invalid_producer_document"
    assert caught.value.args == ("invalid_producer_document",)
    assert not observed
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert secret not in "".join(traceback.format_exception(caught.value))
    assert not caplog.records
    assert capsys.readouterr() == ("", "")
    assert not list(producer.journal_dir.iterdir())
    assert not list(producer.spool_dir.iterdir())


def test_valid_nested_models_preserve_document_retry_identity(producer):
    from decision_mesh.contracts import DecisionSnapshot, Provenance, SourceContext

    values = document(
        snapshot=DecisionSnapshot(
            kind="question",
            provenance=(Provenance(field="title", asserted_by="agent"),),
        ),
        source_context=SourceContext(producer_kind="explicit", thread_id="thread-one"),
        idempotency_key="same-nested-document",
    )
    first = producer.create(values)
    retry = producer.create(ProducerDocument(**values))
    assert retry.duplicate
    assert replace(retry, duplicate=False) == first
