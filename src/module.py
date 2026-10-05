from __future__ import annotations

from embervault_sdk import ModuleContext, ModuleResult
from copy import deepcopy
import json
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

MODULE_ID = "embervault.troubleshooter"
ALLOWED_SEVERITIES = {"info", "attention", "critical"}
ALLOWED_STATUSES = {"observed", "blocked", "missing", "unsupported", "unverified"}


def describe() -> dict:
    return {"id": MODULE_ID, "execution": "embedded", "application_state": "read-only", "mutates_workspace": False}


def scan_evidence(context: ModuleContext, evidence: dict) -> ModuleResult:
    """Summarize version-one evidence supplied by an owning module."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(evidence, dict) or evidence.get("contract_version") != 1:
        return ModuleResult("blocked", "Diagnostic evidence requires contract version 1.")
    producer = evidence.get("producer")
    findings = evidence.get("findings")
    if not isinstance(producer, str) or not producer.strip() or not isinstance(findings, list):
        return ModuleResult("blocked", "Diagnostic evidence requires a producer and findings list.")
    result = scan(context, findings)
    if result.status != "ready":
        return result
    data = dict(result.data)
    data["evidence_contract"] = {"contract_version": 1, "producer": producer.strip()}
    data["source_operation"] = str(evidence.get("operation", "unspecified"))
    return ModuleResult("ready", "Version-one diagnostic evidence summarized.", data)


def export_report(result: ModuleResult) -> dict:
    """Create a sanitized, read-only report payload from a diagnostic result."""
    if not isinstance(result, ModuleResult) or result.status != "ready" or not isinstance(result.data, dict):
        raise ValueError("Only a ready diagnostic result can be exported.")
    return {"report_version": 1, "status": result.status, "message": result.message,
            "data": result.data, "read_only": True, "mutates_workspace": False,
            "export_boundary": "diagnostic-evidence-only"}


def compare_reports(previous: dict, current: dict) -> dict:
    """Compare two sanitized reports without storing or altering either report."""
    for report in (previous, current):
        if not isinstance(report, dict) or report.get("report_version") != 1:
            raise ValueError("Report comparison requires version-one reports.")
        if not isinstance(report.get("data"), dict) or not isinstance(report["data"].get("findings"), list):
            raise ValueError("Reports must contain a findings list.")
    before = {str(item.get("id")): item for item in previous["data"]["findings"] if isinstance(item, dict) and item.get("id")}
    after = {str(item.get("id")): item for item in current["data"]["findings"] if isinstance(item, dict) and item.get("id")}
    added = sorted(set(after) - set(before))
    resolved = sorted(set(before) - set(after))
    changed = sorted(key for key in set(before) & set(after) if before[key] != after[key])
    unchanged = sorted(key for key in set(before) & set(after) if before[key] == after[key])
    return {"comparison_version": 1, "added": added, "resolved": resolved, "changed": changed,
            "unchanged": unchanged, "counts": {"added": len(added), "resolved": len(resolved),
            "changed": len(changed), "unchanged": len(unchanged)}, "read_only": True,
            "mutates_workspace": False}


class ReportHistory:
    """Bounded in-memory history for sanitized diagnostic reports."""

    def __init__(self, limit: int = 10):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("Report history limit must be a positive integer.")
        self._limit = limit
        self._reports: list[dict] = []

    def add(self, report: dict) -> None:
        if not isinstance(report, dict) or report.get("report_version") != 1:
            raise ValueError("Only version-one reports can be retained.")
        if report.get("read_only") is not True or report.get("mutates_workspace") is not False:
            raise ValueError("Only explicitly read-only reports can be retained.")
        data = report.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            raise ValueError("Reports must contain sanitized findings.")
        sanitized = {"report_version": 1, "status": report.get("status"), "message": str(report.get("message", "")),
                     "data": {"findings": deepcopy(data["findings"]), "finding_count": len(data["findings"])},
                     "read_only": True, "mutates_workspace": False}
        self._reports.append(sanitized)
        self._reports[:] = self._reports[-self._limit:]

    def list(self) -> list[dict]:
        return deepcopy(self._reports)

    def compare_latest(self) -> dict:
        if len(self._reports) < 2:
            raise ValueError("At least two reports are required for comparison.")
        return compare_reports(self._reports[-2], self._reports[-1])


class EncryptedReportHistory(ReportHistory):
    """Optional encrypted local store for sanitized diagnostic reports."""

    def __init__(self, path: str | Path, key: bytes, limit: int = 10):
        super().__init__(limit)
        if not isinstance(key, bytes) or not key:
            raise ValueError("An explicit encryption key is required.")
        self._path = Path(path)
        try:
            self._cipher = Fernet(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("The encryption key is invalid.") from exc

    def save(self) -> None:
        payload = json.dumps(self.list(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(self._path.name + ".tmp")
        temporary.write_bytes(self._cipher.encrypt(payload))
        temporary.replace(self._path)

    def load(self) -> None:
        if not self._path.is_file():
            return
        try:
            reports = json.loads(self._cipher.decrypt(self._path.read_bytes()).decode("utf-8"))
        except (InvalidToken, OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Encrypted report history could not be verified.") from exc
        if not isinstance(reports, list):
            raise ValueError("Encrypted report history is invalid.")
        self._reports.clear()
        for report in reports:
            self.add(report)

    def delete(self) -> None:
        """Delete the encrypted history file and clear in-memory reports."""
        self._reports.clear()
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass

    def clear(self) -> None:
        """Clear all reports and persist an empty encrypted history."""
        self._reports.clear()
        self.save()


def execute_history_action(context: ModuleContext, history: EncryptedReportHistory,
                           action: str, approved: bool) -> ModuleResult:
    """Execute an explicitly approved report-store action only."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(history, EncryptedReportHistory) or action not in {"save", "clear", "delete"}:
        return ModuleResult("blocked", "Unsupported report-history action or store.")
    if approved is not True:
        return ModuleResult("blocked", "Report-history execution requires explicit approval.")
    if action == "save":
        history.save()
    elif action == "clear":
        history.clear()
    else:
        history.delete()
    return ModuleResult("ready", "Approved report-history action completed.", {
        "action": action, "approved": True, "read_only": True,
        "mutates_workspace": False, "target": "encrypted-diagnostic-report-store",
    })


def check_module_health(context: ModuleContext, manifest: dict) -> ModuleResult:
    """Validate a supplied module manifest without loading or changing the module."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(manifest, dict):
        return ModuleResult("blocked", "A module manifest object is required.")
    required = ("id", "name", "version", "contract_version", "safety", "operation_types")
    missing = [key for key in required if key not in manifest]
    if missing:
        return ModuleResult("blocked", "Module manifest is missing required fields.", {"missing": missing})
    safety = manifest["safety"]
    if manifest["contract_version"] != 1 or not isinstance(safety, dict) or safety.get("read_only") is not True:
        return ModuleResult("blocked", "Module manifest does not meet the read-only version-one boundary.")
    if not isinstance(manifest["operation_types"], list) or not manifest["operation_types"]:
        return ModuleResult("blocked", "Module manifest must declare operation types.")
    return ModuleResult("ready", "Read-only module health check completed.", {
        "module": {"id": str(manifest["id"]), "name": str(manifest["name"]), "version": str(manifest["version"])},
        "contract_version": 1, "read_only": True, "mutates_workspace": False,
        "checks": {"required_fields": "passed", "contract_version": "passed", "read_only": "passed", "operation_types": "passed"},
    })


def review_evidence_gaps(context: ModuleContext, evidence: dict) -> ModuleResult:
    """Report missing or unsupported evidence without inferring runtime behavior."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(evidence, dict) or evidence.get("contract_version") != 1:
        return ModuleResult("blocked", "Evidence-gap review requires contract version 1.")
    records = evidence.get("evidence")
    if not isinstance(records, list):
        return ModuleResult("blocked", "Evidence-gap review requires an evidence list.")
    gaps = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or not record.get("id"):
            return ModuleResult("blocked", "Every evidence entry requires an id.")
        state = str(record.get("state", "missing")).lower()
        if state in {"missing", "unsupported", "blocked", "unverified"}:
            guidance = {
                "missing": "Collect the required evidence from the owning module.",
                "unsupported": "Review the capability boundary before relying on this result.",
                "blocked": "Resolve the safety or contract prerequisite in the owning module.",
                "unverified": "Run an approved offline or runtime validation before promotion.",
            }[state]
            gaps.append({"id": str(record["id"]), "state": state,
                         "summary": str(record.get("summary", "Evidence requires review.")),
                         "guidance": guidance})
    gaps.sort(key=lambda item: (item["state"], item["id"]))
    return ModuleResult("ready", "Evidence-gap review completed.", {
        "contract_version": 1, "gap_count": len(gaps), "gaps": gaps,
        "read_only": True, "mutates_workspace": False,
    })


def review_recovery_evidence(context: ModuleContext, evidence: dict) -> ModuleResult:
    """Classify Save Manager recovery evidence without inspecting save contents."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        return ModuleResult("blocked", "Recovery evidence requires schema version 1.")
    sources = evidence.get("sources")
    if not isinstance(sources, dict) or not sources:
        return ModuleResult("blocked", "Recovery evidence requires named source reports.")
    findings = []
    for name in ("source_backup", "current_state_backup", "restored_target"):
        report = sources.get(name)
        if not isinstance(report, dict):
            findings.append({"id": name, "title": f"Missing {name}", "severity": "critical", "status": "missing"})
        elif report.get("state") != "ready":
            findings.append({"id": name, "title": f"{name} is not ready", "severity": "critical", "status": "blocked"})
    if evidence.get("validated") is not True:
        findings.append({"id": "recovery-validation", "title": "Recovery validation incomplete", "severity": "critical", "status": "unverified"})
    if evidence.get("mutated_files") is not False:
        findings.append({"id": "mutation-boundary", "title": "Recovery mutation boundary is not confirmed", "severity": "critical", "status": "unsupported"})
    compatibility = evidence.get("compatibility")
    if compatibility is not None and compatibility not in {"supported", "unknown", "unsupported"}:
        return ModuleResult("blocked", "Recovery compatibility state is unsupported.")
    if compatibility in {"unknown", "unsupported"}:
        findings.append({"id": "compatibility", "title": "Recovery compatibility is not confirmed", "severity": "attention", "status": "unsupported"})
    result = scan(context, findings)
    data = dict(result.data) if result.status == "ready" else {}
    data.update({"recovery_schema_version": 1, "operation_id": str(evidence.get("operation_id", "unspecified")),
                 "rollback_ready": not findings and evidence.get("validated") is True,
                 "read_only": True, "mutates_workspace": False})
    return ModuleResult("ready", "Recovery evidence review completed.", data)


def check_package_health(context: ModuleContext, package: dict) -> ModuleResult:
    """Validate package metadata supplied by an owning module or Control Center."""
    if context.module_id != MODULE_ID:
        return ModuleResult("blocked", "Troubleshooter received an invalid module context.")
    if not isinstance(package, dict):
        return ModuleResult("blocked", "A package metadata object is required.")
    required = ("id", "name", "version", "manifest_version")
    missing = [key for key in required if not package.get(key)]
    if missing:
        return ModuleResult("blocked", "Package metadata is incomplete.", {"missing": missing})
    if package.get("manifest_version") != 1:
        return ModuleResult("blocked", "Package manifest version is unsupported.")
    dependencies = package.get("dependencies", [])
    if not isinstance(dependencies, list) or any(not isinstance(item, str) or not item.strip() for item in dependencies):
        return ModuleResult("blocked", "Package dependencies must be a list of names.")
    if len(set(dependencies)) != len(dependencies):
        return ModuleResult("blocked", "Package dependencies must not contain duplicates.")
    return ModuleResult("ready", "Read-only package health check completed.", {
        "package": {key: str(package[key]) for key in ("id", "name", "version")},
        "manifest_version": 1, "dependencies": sorted(dependencies),
        "checks": {"identity": "passed", "manifest_version": "passed", "dependencies": "passed"},
        "read_only": True, "mutates_workspace": False,
    })


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
