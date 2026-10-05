# Decision Mesh candidate quickstart

Status: application alpha, undergoing release qualification. The Python package has not been uploaded to PyPI. The published npm bootstrap supplies event-schema tools only. Use these steps with a checked local Python candidate, not as a claim of a stable release.

## Install

Requires Python 3.12 or newer. Recorded Windows checks include a full suite on Python 3.13.14 and a bounded installation, runtime, reinstall and uninstall check on 3.12.12. These development-candidate checks do not establish clean-machine or native-host support. Use a dedicated virtual environment and a reviewed wheel:

```sh
python -m venv .decisionmesh-env
.decisionmesh-env/Scripts/python.exe -m pip install /absolute/path/to/decision_mesh-0.1.0a1-py3-none-any.whl
.decisionmesh-env/Scripts/decisionmesh.exe --help
```

The remaining examples use `decisionmesh` to mean that installed executable. Activate the environment or use its full path. Replace every angle-bracket placeholder with your own path before running a command.

## Verify local reporting

Choose a dedicated absolute data directory, separate from application source or an unrelated workspace. This explicit check starts a local-only runtime if needed, exercises synthetic local capture and committed ingestion, and records its result:

```sh
decisionmesh setup --verify-local --local-only --data-dir <absolute-data-directory>
decisionmesh setup --status --data-dir <same-data-directory>
decisionmesh doctor --data-dir <same-data-directory>
decisionmesh open --local-only --data-dir <same-data-directory>
```

The local check verifies the installed runtime and synthetic reporting path. It does not qualify native host hooks, grant permissions, or enable Telegram. Status and doctor are read-only. Repeat verification to check recovery after a problem. Its output distinguishes local success from notification readiness; an outstanding reconciliation state must be resolved before external sending.

The inbox opens in your browser. Friendly and Compact layouts show the same evidence. Questions reported by an agent remain labeled as reported observations. Seen and Snooze affect local attention, not the original host's approval state. History retains aged observations; an empty inbox does not prove the agent is idle.

To let an agent report actual task questions, explicitly enroll the producer and enable the [advisory skill](agent-skill.md):

```sh
decisionmesh producer enroll --data-dir <same-data-directory>
```

A successful producer receipt means local spool acceptance; inspect the inbox for ingestion and later delivery status. Producer commands do not launch the runtime. Keep the original conversation available if reporting itself requires host permission.

## Optional Telegram setup

Stop a local-only runtime before opening normal setup. Changing the command flag does not change the mode of an already running process:

```sh
decisionmesh stop --data-dir <same-data-directory>
decisionmesh setup --data-dir <same-data-directory>
```

1. Create or choose a bot using Telegram's official [BotFather instructions](https://core.telegram.org/bots/tutorial#obtain-your-bot-token). Enter its token directly into the local Settings form; keep it out of prompts, terminal arguments and public issues.
2. Choose **Validate token and store securely**. If the approved Windows credential backend is unavailable, local reporting remains usable and external sends stay disabled.
3. Start a private chat with that bot yourself. Choose **Discover user-initiated private chat**, follow the displayed one-time pairing-code instructions, and verify the selected recipient.
4. Review the exact synthetic preview, then choose **Send this exact test to the selected recipient** only when you want that message sent.
5. A successful test keeps ongoing notifications off. Separately enable **Telegram channel active**, select Immediate or Digest delivery and the digest interval, review the external preview, and apply the changes.

Default alerts disclose minimal fields. Select additional fields only when you intend to share them externally. Turning the channel off and back on does not automatically forward older private observations. Pause retains the route; turning the channel off revokes the current delivery generation.

If setup or policy reconciliation failed, repair the displayed cause before explicitly requesting reconciliation:

```sh
decisionmesh setup --reconcile --data-dir <same-data-directory>
```

Read its result before assuming notifications are ready. Provider acceptance does not establish delivery to a device, reading, native approval or resumed work. Telegram response handling and remote approval are not part of this release.

## Stop, backup and update

Stop the runtime before backup, update or uninstall:

```sh
decisionmesh stop --data-dir <same-data-directory>
decisionmesh backup --data-dir <same-data-directory> --destination <new-absolute-backup-path>
```

A backup excludes credentials. Keep it protected as it contains local request data. Install the next checked wheel with the same environment's Python and `pip install --upgrade`, then rerun diagnostics and local verification. Cross-version upgrade qualification is still a release gate; the current package checks establish only same-version reinstall preservation.

Restore requires a new data directory and an absolute backup path:

```sh
decisionmesh restore --data-dir <new-absolute-data-directory> --backup <absolute-backup-path>
```

Restoration disables notifications until deliberate setup and reconciliation. Do not copy runtime authentication files or bot credentials from the old directory.

## Optional startup and uninstall

Autostart and shortcuts are off by default. Native Windows qualification is pending. For a candidate test, `setup --windows-integration install` prints a proposed owned integration plan; application requires the exact displayed plan digest. Review its executable, paths and requested features. Setup checks existing entries against its ownership records and refuses mismatches. Avoid changing these entries in another program while setup runs. Do not enable this before the installed-path and Windows checks are complete.

If you installed owned Windows integration, stop the runtime, inspect `setup --windows-integration remove` and apply that reviewed plan before uninstalling the Python package. Ordinary package uninstall deliberately preserves your data:

```sh
python -m pip uninstall decision-mesh
```

Use the same environment that installed the package. Data deletion and removal of credentials are separate deliberate actions; package uninstall is not proof that all stored data or OS integration has been removed.

Windows integration also retains a small coordination lock in your Windows Local AppData folder under `DecisionMesh-Integration`. It lets separate installations coordinate their changes and contains no request content or credentials. Leave it in place while any Decision Mesh installation is in use.

## Current support limits

Native Codex prompt and closure tracking is disabled/unqualified. The capture executable is an observation adapter, not proof of a working desktop integration. Do not install/trust hooks or change agent permissions merely because this package exists. Respond in the original agent interface.

Real notification, native-host, installed browser, sleep/recovery and Windows startup checks remain release gates. Diagnostics report unknown or unavailable evidence explicitly. See the root SECURITY document for privacy boundaries and the repository's private vulnerability-reporting route.
