# Troubleshooter Roadmap

## Current state

- Read-only embedded module with SDK context validation.
- Deterministic diagnostic finding normalization and summary counts.
- Findings can be observed, blocked, or unsupported; no finding can authorize repair or mutation.
- Evidence and recovery boundaries explicitly state that output is informational only.
- Version-one evidence intake accepts producer-tagged findings from Save Manager and other owning modules.
- Sanitized report export preserves the read-only boundary.

## Next slices

1. Accept validated diagnostics from Control Center through the same versioned evidence contract.
2. Add package/module health checks and evidence-gap review.
3. Add deterministic severity, evidence-gap, and recovery-risk review workflows.
4. Add integration tests for SDK manifests, Content Creator handoff, and shared CI.

## Boundaries

Troubleshooter does not edit saves, game files, installed mods, or configuration. Repairs remain outside the module and require the owning authority, verified backup, explicit preview, and post-operation validation.
