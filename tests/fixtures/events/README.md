# Event replay fixtures

These are synthetic events for deterministic contract/reducer verification, not empirical Codex capture or compatibility evidence.

- `producer-lifecycle.json`: opened, identical replay, agent-reported resolution, attempted resurrection. Expected categories are apply/duplicate/apply/conflict.
- `native-continuity.json`: qualified synthetic pending snapshot, disconnect, last-known update, per-request reconciliation, closed-with-answer-unknown, explicit outcome correction. Expected states and confirmation flags are recorded separately from the reducer output.

Runtime import must call `validate_event(raw, now=received_at)` before projection, inject a registered `SourceCapabilities` manifest, and preserve compact event/revision identities across detail pruning. These fixtures deliberately do not establish a real host manifest.
