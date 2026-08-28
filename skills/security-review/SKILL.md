---
name: security-review
description: Review code for confirmed exploitable vulnerabilities by tracing attacker-controlled input across the codebase. Use for security reviews of files, diffs, or repositories where false-positive control matters.
---

# High-Confidence Security Review

Report only findings where a vulnerable operation and attacker-controlled input are both confirmed. The reporting scope is the user-selected file, diff, or component, but research surrounding routes, validation, configuration, middleware, and framework protections throughout the repository.

Do not flag tests, dead code, constants, deployment configuration, environment variables, or framework-safe defaults without a real attacker path. Distinguish server-controlled URLs from request-controlled URLs for SSRF. Check auto-escaping and parameterization before reporting XSS or injection.

For each candidate, trace source to sink, look for upstream validation and authorization, verify reachability, then state confidence. Put uncertain candidates under `Needs verification`; do not present them as vulnerabilities. Report location, severity, impact, concise evidence, and remediation. If none qualify, say that no high-confidence vulnerabilities were identified.

Source adaptation: getsentry security-review skill supplied by the user.
