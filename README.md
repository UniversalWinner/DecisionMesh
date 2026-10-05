# Decision Mesh

Decision Mesh is an open-source local inbox for AI-agent questions, permission observations, and notifications. It keeps request evidence, notification delivery, and agent execution separate so a notification never pretends to be an approval.

**Status: application alpha under development and independent review. Not yet a production-ready or qualified native-host release.** The public npm bootstrap provides structural event-schema tools only. This Python source includes the developing runtime and local inbox; no PyPI publication is claimed here.

## Implemented components

- A durable SQLite request store, explicit producer API, and replay/recovery behavior.
- A loopback authenticated inbox with compact/friendly presentation and request history.
- Immediate or timed notification scheduling, with optional Telegram pairing and disclosure controls.
- A local CLI for starting/opening/stopping the runtime, diagnostics, and conservative backup/restore.
- Opt-in Windows startup/shortcut planning; native installation and recovery remain under qualification.

Independent review has accepted several component libraries. Runtime and integration acceptance and real-world qualification are still in progress. Native Codex request capture is disabled and unqualified; a permission-gate observation does not establish that a prompt was displayed or resolved. Respond to native requests in the original agent interface. Progress Mesh integration is planned for a later release.

## Local development candidate

Requires Python 3.12 or newer. Recorded Windows checks include a full suite on Python 3.13.14 and a bounded installed smoke test on 3.12.12. Clean-machine and native-host support remain unqualified. Start with the [source repository](https://github.com/UniversalWinner/DecisionMesh) and follow [Contributing](CONTRIBUTING.md) to build and inspect a fresh wheel. Build outputs are not committed. The documented candidate build produces this installation path:

```sh
python -m pip install ./dist/candidate/decision_mesh-0.1.0a1-py3-none-any.whl
decisionmesh --help
decisionmesh doctor
```

For a disposable local-only trial, choose a new absolute data-directory path. Local-only mode disables credential access and external sends for a newly started runtime. Opening the inbox starts the installed runtime and launches the system browser:

```sh
decisionmesh open --local-only --data-dir <absolute-new-data-directory>
decisionmesh stop --data-dir <same-data-directory>
```

Replace the angle-bracket placeholders before running the commands. Do not use an unrelated project's directory. See the [candidate quickstart](docs/public/quickstart.md) and [advisory skill guide](docs/public/agent-skill.md). Installed setup, upgrade and browser qualification remain release checks; this section is not a stable user rollout claim.

## Notifications and privacy

Telegram is optional. Enduring bot credentials use the verified Windows Credential Manager backend; unavailable or invalid credentials prevent external sends while local use remains available. Pairing shows the destination and exact synthetic test first. A successful test leaves ongoing notifications inactive; enabling them is a separate settings choice. Provider acceptance does not prove device delivery or reading.

Local request files and database are restricted to the OS account but are not encrypted. Default external alerts use minimal fields. Broader disclosure requires the corresponding explicit settings. Diagnostic exports are restricted to fixed operational fields. See [SECURITY.md](SECURITY.md) for boundaries and current qualification limits.

## Contributing and support

See [CONTRIBUTING.md](CONTRIBUTING.md) and [VISION.md](VISION.md). MIT licensed. The project repository is [UniversalWinner/DecisionMesh](https://github.com/UniversalWinner/DecisionMesh). A verified optional donation destination has not yet been configured; no payment or subscription is required for the open-source functionality.
