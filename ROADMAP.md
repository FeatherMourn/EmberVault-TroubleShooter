# Troubleshooter Roadmap

## Current state

- Read-only embedded module with SDK context validation.
- Deterministic diagnostic finding normalization and summary counts.
- Findings can be observed, blocked, or unsupported; no finding can authorize repair or mutation.
- Evidence and recovery boundaries explicitly state that output is informational only.
- Version-one evidence intake accepts producer-tagged findings from Save Manager and other owning modules.
- Sanitized report export preserves the read-only boundary.
- Supplied module manifests can be health-checked without loading or changing modules.
- Evidence gaps are surfaced explicitly as missing, unsupported, blocked, or unverified.
- Package metadata can be health-checked without installation or mutation.
- Evidence-gap results include bounded follow-up guidance without promoting unsupported claims.
- Package dependency metadata is checked for shape and duplicates without resolution or installation.
- Repository CI runs the full Troubleshooter test file on pushes and pull requests.
- CI checks the embedded Control Center Troubleshooter contract against the version-one evidence payload.
- Read-only report comparison identifies added, resolved, changed, and unchanged findings.
- Bounded in-memory history retains sanitized report summaries and supports latest comparison.
- Optional encrypted local history persists sanitized summaries with explicit key ownership and verification.
- Encrypted history supports atomic writes, explicit deletion, empty-history reset, and corruption handling.
- Approved save, clear, and delete execution is bounded to the encrypted diagnostic report store.
- Packaged runtime requests resolve key references through an injected provider and never accept raw keys.
- Save Manager recovery evidence is classified for backup readiness, compatibility, rollback readiness, and mutation boundaries.

## Next slices

1. Connect Control Center approval results to the packaged runtime request contract.
2. Add cross-repository Save Manager recovery-evidence contract tests.
2. Persist and export sanitized reports without retaining private game contents.
3. Add richer Save Manager recovery, compatibility, and backup-evidence diagnostics.
4. Add Control Center package and module inventory checks.
5. Add evidence retention, contradiction review, and recovery-risk workflows.
6. Expand cross-repository CI for SDK, Control Center, Save Manager, and Troubleshooter contracts.
7. Build a read-only Troubleshooter interface for scan review and report comparison.

## Boundaries

Troubleshooter does not edit saves, game files, installed mods, or configuration. Repairs remain outside the module and require the owning authority, verified backup, explicit preview, and post-operation validation.
