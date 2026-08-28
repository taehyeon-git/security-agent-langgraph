---
name: dependency-scanning
description: Scan third-party package manifests and lockfiles for known vulnerabilities and remediation paths. Use for software composition analysis, dependency audits, and supply-chain security gates.
---

# Dependency Scanning

Discover the ecosystem from manifests and lockfiles, and prefer scanning the resolved lockfile over an unconstrained manifest. Use the ecosystem-native auditor when available (for example `pip-audit`, `npm audit`, `cargo audit`, or `govulncheck`) and preserve the package manager's structured output.

For every finding, report package, installed version, advisory identifier, affected range, fixed version, reachability evidence when available, and upgrade impact. Separate direct from transitive dependencies and do not claim exploitability solely from a version match. Prefer the smallest compatible upgrade, then regenerate the lockfile and run tests. Never silently apply major upgrades.

For CI, fail according to a documented severity policy and account for unavailable advisory services. Do not send private manifests or source to third-party services without approval.

Source adaptation: BagelHole dependency-scanning skill supplied by the user.
