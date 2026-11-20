# Security policy

DeadBolt is a defensive tool. By design it:

- makes no network calls (the opt-in `--llm-triage` client is restricted to loopback hosts and bypasses proxies)
- never validates a discovered credential against a live service
- never prints, stores or transmits a raw secret: every output is redacted to `prefix****last4` plus a truncated sha256 fingerprint
- never changes code, history, keys or cloud resources: it only writes proposals for a human to approve

**Reporting a vulnerability:** please open a private security advisory on this repository
(Security → Advisories → Report a vulnerability) rather than a public issue.

**False negatives / false positives:** open an issue with a *synthetic* reproduction. Please never paste a real credential.
