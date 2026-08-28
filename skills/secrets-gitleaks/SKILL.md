---
name: secrets-gitleaks
description: Detect and prevent hardcoded credentials with Gitleaks in working trees, staged changes, or Git history. Use for secret audits, baselines, hooks, CI integration, and exposure remediation.
---

# Secrets Detection with Gitleaks

Choose scan scope deliberately: current files, staged changes, or full Git history. Use redaction in all human-readable output and structured JSON or SARIF for automation. Review allowlists as code; never suppress a finding merely to pass a gate.

When a likely secret is found, do not print it. Report detector type, file, line, commit when relevant, and fingerprint only if already safely redacted. The first remediation is revocation or rotation; deleting the current file does not remove history. History rewrites and force pushes are destructive and require separate explicit approval and contributor coordination.

For prevention, recommend staged-change hooks and CI checks with full history where appropriate. Test custom rules with synthetic values and both positive and negative cases.

Source adaptation: aiskillstore secrets-gitleaks skill supplied by the user.
