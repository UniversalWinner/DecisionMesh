# Using the advisory agent skill

Status: packaged for the application alpha; live host invocation qualification remains pending. The npm bootstrap is a schema utility and does not install this skill or the Python application.

The Python distribution includes a `resources/decision-mesh` folder containing `SKILL.md`, a producer reference and a synthetic example. Locate the installed folder:

```sh
python -c "from importlib.resources import files; print(files('decision_mesh').joinpath('resources/decision-mesh'))"
```

Copy that folder to a skill directory supported by your agent host, following that host's setup instructions. Preserve existing skills instead of overwriting an existing folder. Enable Decision Mesh reporting for the intended task. Skill discovery and invocation are controlled by the agent host; this package does not disable automatic discovery or promise explicit-only invocation. In Codex, automatic discovery remains at its default. Discovery alone does not authorize reporting, setup or external delivery. Copying it does not trust hooks, change host permissions, configure notifications or enroll a producer.

The user must first choose the app's absolute data directory and enroll the explicit producer. Communicate that configured path to the agent without adding any bot credentials to its prompt. The installed `decisionmesh` command must be accessible in the agent's execution environment.

During use, the agent can record its questions and update their agent-reported status. It still asks for and receives any required authority in the original host. If the host requires permission to execute the reporting helper, the skill keeps the request in the normal conversation and avoids recursive reporting attempts. Native permission capture remains separately disabled/unqualified until its platform checks pass.

The skill's successful producer receipt proves local spool acceptance only. Use the inbox to inspect ingestion and delivery status. Notifications require independent user setup and activation.
