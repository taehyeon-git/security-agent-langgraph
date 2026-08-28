---
name: semgrep-rule-authoring
description: Create, debug, or validate custom Semgrep rules with positive and negative tests. Use for Semgrep YAML rule development, not routine repository scans.
---

# Semgrep Rule Authoring

Choose pattern matching for local syntax and taint mode for source-to-sink flows. Write annotated tests first with `ruleid:` for true positives and `ok:` for safe cases. Inspect the language AST when syntax is ambiguous, then implement the smallest rule that distinguishes those cases.

Validate YAML, run `semgrep --test`, and require all expected and unexpected lines to pass before optimizing. Use `pattern-either`, `pattern-not`, `pattern-inside`, `pattern-not-inside`, and metavariable constraints deliberately to reduce false positives. Add dataflow traces when debugging taint rules. Always include `--metrics=off` on commands that support it and never place real credentials in fixtures.

Deliver the rule, tests, commands run, and remaining language or framework limitations.

Source adaptation: official Semgrep skill page supplied by the user.
