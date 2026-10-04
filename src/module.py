from __future__ import annotations

from embervault_sdk import ModuleContext, ModuleResult

MODULE_ID = "embervault.troubleshooter"


def describe() -> dict:
    return {"id": MODULE_ID, "execution": "embedded", "application_state": "read-only", "mutates_workspace": False}


def scan(context: ModuleContext, findings: list[dict]) -> ModuleResult:
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("title") or not finding.get("severity"):
            return ModuleResult("blocked", "Diagnostic findings must include a title and severity.")
        normalized.append({"title": str(finding["title"]), "severity": str(finding["severity"]),
                           "message": str(finding.get("message", ""))})
    return ModuleResult("ready", "Read-only diagnostic scan completed.", {
        "findings": normalized, "attention_count": sum(item["severity"] == "attention" for item in normalized),
        "application_state": "read-only", "mutates_workspace": False,
        "evidence": [{"id": "diagnostic-scan", "kind": "test", "state": "observed", "summary": "Read-only diagnostic findings collected."}],
        "recovery": {"expectation": "No repair or mutation", "rollback": "Discard diagnostic output", "verification": "Confirm workspace is unchanged", "backup_required": False},
    })
