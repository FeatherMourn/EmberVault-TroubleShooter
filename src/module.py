from __future__ import annotations

from embervault_sdk import ModuleContext, ModuleResult

MODULE_ID = "embervault.troubleshooter"
ALLOWED_SEVERITIES = {"info", "attention", "critical"}
ALLOWED_STATUSES = {"observed", "blocked", "unsupported"}


def describe() -> dict:
    return {"id": MODULE_ID, "execution": "embedded", "application_state": "read-only", "mutates_workspace": False}


def scan(context: ModuleContext, findings: list[dict]) -> ModuleResult:
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("title") or not finding.get("severity"):
            return ModuleResult("blocked", "Diagnostic findings must include a title and severity.")
        severity = str(finding["severity"]).lower()
        status = str(finding.get("status", "observed")).lower()
        if severity not in ALLOWED_SEVERITIES:
            return ModuleResult("blocked", "Diagnostic severity is not supported.")
        if status not in ALLOWED_STATUSES:
            return ModuleResult("blocked", "Diagnostic status is not supported.")
        if any(key in finding for key in ("repair", "action", "write", "mutation")):
            return ModuleResult("blocked", "Troubleshooter findings cannot authorize repairs or mutations.")
        normalized.append({"id": str(finding.get("id", f"finding-{len(normalized) + 1}")),
                           "title": str(finding["title"]), "severity": severity, "status": status,
                           "message": str(finding.get("message", ""))})
    normalized.sort(key=lambda item: (item["severity"], item["status"], item["id"], item["title"]))
    severity_counts = {severity: sum(item["severity"] == severity for item in normalized)
                       for severity in sorted(ALLOWED_SEVERITIES)}
    status_counts = {status: sum(item["status"] == status for item in normalized)
                     for status in sorted(ALLOWED_STATUSES)}
    return ModuleResult("ready", "Read-only diagnostic scan completed.", {
        "schema_version": 1, "findings": normalized,
        "finding_count": len(normalized), "attention_count": severity_counts["attention"],
        "severity_counts": severity_counts, "status_counts": status_counts,
        "application_state": "read-only", "mutates_workspace": False,
        "evidence": [{"id": "diagnostic-scan", "kind": "test", "state": "observed", "summary": "Read-only diagnostic findings collected."}],
        "recovery": {"expectation": "No repair or mutation", "rollback": "Discard diagnostic output", "verification": "Confirm workspace is unchanged", "backup_required": False},
    })
