---
name: threat-model-generation
description: Generate or update a repository threat model using STRIDE. Use after architecture changes, during security setup, or for an explicit threat-modeling audit.
---

# STRIDE Threat Model Generation

Inspect manifests, entry points, services, APIs, storage, external integrations, authentication, authorization, secrets, and deployment topology. Map components, data flows, trust boundaries, entry points, privileged operations, and critical assets before enumerating threats.

Apply STRIDE to each relevant component and boundary: spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege. Rank threats by likelihood and impact, record existing controls, gaps, mitigations, assumptions, and accepted risks. Do not invent architecture; mark missing evidence explicitly.

Return a Markdown model optimized for later security reviews, including system overview, attack surface, asset classification, STRIDE table, abuse cases, prioritized mitigations, and testing strategy. Write repository files only when the user requests persistence.

Source adaptation: Factory AI threat-model-generation skill supplied by the user.
