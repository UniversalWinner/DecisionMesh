# Security and privacy

Status: prerelease implementation under review. A production-ready security claim is not made. Stable release requires independent review, dependency/static/secret checks, integration and recovery checks, real supported-platform qualification, and no unresolved Critical or High findings.

Decision Mesh's boundary is a local OS account. Owner-restricted files and a loopback authenticated service protect against unintended access; they are not protection against malicious software already controlling that account or an administrator. Local data is not encrypted. Use an account and workspace you control.

The local service binds to the IPv4 loopback address on a runtime-selected port. An authenticated local command exchanges a short-lived browser nonce; the control secret must not be shared. Request content, credentials, private paths and control authentication are excluded from diagnostic exports. No remote approval endpoint is provided. The native agent remains the permission authority.

Optional Telegram sends use the exact selected bot/recipient and explicit disclosure settings. Credentials are stored only through the approved Windows Credential Manager backend, with no plaintext fallback. Revocation, changed destination, ambiguous sends, restart and retry each have distinct states. A provider's success response is not proof of receipt, reading, approval or agent execution.

Windows autostart/shortcut integration is optional and off by default. Ownership-preserving repair and uninstall are mandatory; known review findings must close before those features are accepted. Native hooks are disabled until their host-specific behavior is qualified; merely creating a file never establishes host trust.

## Reporting

Private vulnerability reporting is enabled for this repository. Use [Report a vulnerability](https://github.com/UniversalWinner/DecisionMesh/security/advisories/new) while signed into GitHub for security-sensitive reports. Use [repository issues](https://github.com/UniversalWinner/DecisionMesh/issues) for non-sensitive bugs. Include the affected version, expected behavior and a minimal synthetic reproduction; do not attach credentials or private request data. No response-time guarantee or private email service is claimed.
