# Security policy

DeadBolt is a defensive tool. By design it:

- performs core scanning offline; opt-in `--llm-triage` uses numeric loopback connections, bypasses proxies and refuses redirects
- never validates a discovered credential against a live service
- sanitizes detected credentials and URL parameters in output metadata; redaction and detection have finite rule coverage
- leaves remediation to the operator and records local review decisions
- refuses existing demo destinations and reports unreadable or oversized scan inputs as errors

Authority classifications are heuristic estimates. Effective access is unknown. JWT claims are unverified.

Approval names are operator-supplied labels. Proposal hashes identify content, and ledger hashes detect ordinary edits. Independent retention of a trusted ledger head is required to detect recalculated chains or truncation. Use `deadbolt ledger --expected-head <trusted-sha256>` to compare the current ledger with that checkpoint.

**Reporting a vulnerability:** please open a private security advisory on this repository
(Security → Advisories → Report a vulnerability) rather than a public issue.

**False negatives / false positives:** open an issue with a *synthetic* reproduction. Please never paste a real credential.
