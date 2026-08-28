---
name: semgrep-security
description: Run Semgrep static security analysis on source repositories or files. Use for SAST, vulnerability scans, and bug-pattern audits; do not use for authoring a new Semgrep rule.
---

# Semgrep Security Scan

Detect languages and frameworks before selecting explicit rulesets. Never use `--config auto`; every Semgrep invocation must include `--metrics=off` so audit material does not enable telemetry.

Before an external scan, show the target, engine, scan mode, output directory, and exact rulesets and obtain approval. Check whether Semgrep Pro is available; describe the cross-file limitation when only OSS is available. Prefer high-confidence security rules for focused reviews and broader rules only when the user requests full coverage. Preserve raw output and produce JSON or SARIF in a dedicated result directory. Treat matches as leads and validate attacker-controlled data flow before reporting them as exploitable.

Do not expose secret values in findings. Report rule ID, severity, file, line, evidence summary, confidence, and remediation.

Source adaptation: Trail of Bits Semgrep security-scan workflow supplied by the user.
