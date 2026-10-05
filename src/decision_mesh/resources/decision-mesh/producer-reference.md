# Explicit producer reference

The installed Python application provides this interface. The npm schema-tools bootstrap does not provide the application, runtime, or producer command.

## Setup boundary

The user first configures a Decision Mesh data directory, starts the local runtime as needed, and explicitly enrolls the local producer:

```text
decisionmesh producer enroll --data-dir <absolute-configured-data-directory>
```

Enrollment is idempotent. It creates local producer identity; it does not start the runtime or enable notifications. Ordinary reporting does not automatically run enrollment.

## Command interface

Send one JSON object as UTF-8 stdin, no more than 256 KiB, to one operation:

```text
decisionmesh producer create --data-dir <absolute-configured-data-directory>
decisionmesh producer update --data-dir <absolute-configured-data-directory>
decisionmesh producer resolve --data-dir <absolute-configured-data-directory>
decisionmesh producer withdraw --data-dir <absolute-configured-data-directory>
```

Use an argument-array subprocess with its stdin parameter. No request JSON belongs in argv. The four operations accept the same complete document shape shown in [example-request.json](example-request.json).

Required fields: `source_request_id` (1-128 characters, no control characters) and `snapshot.kind` (`question`, `choice`, or `permission`). Supply a meaningful title and summary even though the wire format permits empty strings. Optional `idempotency_key` uses the same identifier limits. Use stable task-specific values, not a fresh random key on every retry.

Snapshot fields include `gate_kind` (`user_authority`, `technical_review`, `platform_permission`, `runtime_admission`, `unclassified`) and `action_category` (`testing`, `implementation`, `download`, `installation`, `general`, `unknown`). Choose only an evidenced category; otherwise use the default unclassified/unknown. Optional details are `task`, `action`, `scope`, `exclusions`, `reason`, and `options`. An update replaces the snapshot; include every detail still intended to remain.

Optional `occurred_at` must be an actual timezone-aware UTC timestamp, not an invented time. Omit it when unknown. `source_context` defaults to the explicit producer. Do not supply host provenance, host authority, native confirmation, generated event IDs/revisions or capture-policy grants. The runtime and producer allocate these boundaries.

## Receipt interpretation

Exit zero and `accepted_to_spool: true` mean local publication succeeded. `ingested: false` is explicit: this command does not synchronously import. Preserve the returned event identity, revision and idempotency key if needed to reconcile an uncertain call; never show opaque IDs as a user's approval choice.

A same-key, same-document retry returns the same allocation. A changed document with a reused key is rejected. A full allocation journal is an explicit failure, not an invitation to delete its duplicate-detection records. Failure output is intentionally redacted. Do not collect tokens, private paths or request contents in diagnostic logs.

## Notification boundary

Settings, original capture-time eligibility, destination generation, disclosure grants and actual runtime health determine notification eligibility. Starting with notifications disabled and enabling them later does not authorize replay of the old private backlog. Do not work around this by recreating stale requests as new. The local inbox can still retain their history.

A provider-accepted Telegram message does not prove device delivery or reading. Resolving a producer-reported request does not grant a native permission, execute code, or resume the agent.
