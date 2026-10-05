import unittest

from embervault_sdk import ModuleContext
from src.module import check_module_health, check_package_health, compare_reports, export_report, review_evidence_gaps, scan, scan_evidence


class TroubleshooterTests(unittest.TestCase):
    def test_scan_is_read_only(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-1"),
                      [{"title": "Module missing", "severity": "attention", "message": "Install it."}])
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["attention_count"], 1)
        self.assertFalse(result.data["mutates_workspace"])
        self.assertEqual(result.data["recovery"]["backup_required"], False)
        self.assertEqual(result.data["evidence"][0]["state"], "observed")

    def test_invalid_finding_is_blocked(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-2"), [{}])
        self.assertEqual(result.status, "blocked")

    def test_summary_is_deterministic_and_sorted(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-3"), [
            {"id": "z", "title": "Critical issue", "severity": "critical", "status": "blocked"},
            {"id": "a", "title": "Informational note", "severity": "info"},
        ])
        self.assertEqual(result.data["schema_version"], 1)
        self.assertEqual([item["id"] for item in result.data["findings"]], ["z", "a"])
        self.assertEqual(result.data["severity_counts"]["critical"], 1)
        self.assertEqual(result.data["status_counts"]["blocked"], 1)

    def test_mutation_instruction_is_blocked(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-4"), [
            {"title": "Repair requested", "severity": "critical", "action": "delete file"},
        ])
        self.assertEqual(result.status, "blocked")

    def test_unknown_severity_is_blocked(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-5"), [
            {"title": "Unknown", "severity": "warning"},
        ])
        self.assertEqual(result.status, "blocked")

    def test_save_manager_evidence_contract_is_accepted(self):
        result = scan_evidence(ModuleContext("embervault.troubleshooter", "default", "EV-OP-6"), {
            "contract_version": 1, "producer": "embervault.save-manager", "operation": "save-inspection",
            "findings": [{"id": "save-1", "title": "Save inspection ready", "severity": "info"}],
        })
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["evidence_contract"]["producer"], "embervault.save-manager")
        self.assertEqual(result.data["source_operation"], "save-inspection")

    def test_unknown_evidence_contract_is_blocked(self):
        result = scan_evidence(ModuleContext("embervault.troubleshooter", "default", "EV-OP-7"), {
            "contract_version": 2, "producer": "embervault.save-manager", "findings": [],
        })
        self.assertEqual(result.status, "blocked")

    def test_report_export_is_sanitized_and_read_only(self):
        result = scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-8"), [
            {"title": "No issue", "severity": "info"},
        ])
        report = export_report(result)
        self.assertEqual(report["report_version"], 1)
        self.assertTrue(report["read_only"])
        self.assertFalse(report["mutates_workspace"])
        self.assertEqual(report["export_boundary"], "diagnostic-evidence-only")

    def test_report_comparison_identifies_added_resolved_changed_and_unchanged(self):
        before = export_report(scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-C1"), [
            {"id": "same", "title": "Same", "severity": "info"},
            {"id": "changed", "title": "Old", "severity": "attention"},
            {"id": "resolved", "title": "Resolved", "severity": "critical"},
        ]))
        after = export_report(scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-C2"), [
            {"id": "same", "title": "Same", "severity": "info"},
            {"id": "changed", "title": "New", "severity": "attention"},
            {"id": "added", "title": "Added", "severity": "info"},
        ]))
        comparison = compare_reports(before, after)
        self.assertEqual(comparison["added"], ["added"])
        self.assertEqual(comparison["resolved"], ["resolved"])
        self.assertEqual(comparison["changed"], ["changed"])
        self.assertEqual(comparison["unchanged"], ["same"])
        self.assertTrue(comparison["read_only"])

    def test_report_comparison_rejects_unknown_version(self):
        with self.assertRaises(ValueError):
            compare_reports({"report_version": 2, "data": {"findings": []}},
                            {"report_version": 1, "data": {"findings": []}})

    def test_module_health_check_accepts_read_only_manifest(self):
        result = check_module_health(ModuleContext("embervault.troubleshooter", "default", "EV-OP-9"), {
            "id": "embervault.save-manager", "name": "Save Manager", "version": "0.1.0",
            "contract_version": 1, "safety": {"read_only": True}, "operation_types": ["save-inspection"],
        })
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["checks"]["read_only"], "passed")

    def test_module_health_check_rejects_mutating_manifest(self):
        result = check_module_health(ModuleContext("embervault.troubleshooter", "default", "EV-OP-10"), {
            "id": "embervault.mod-manager", "name": "Mod Manager", "version": "0.1.0",
            "contract_version": 1, "safety": {"read_only": False}, "operation_types": ["mod-install"],
        })
        self.assertEqual(result.status, "blocked")

    def test_evidence_gap_review_reports_unverified_entries(self):
        result = review_evidence_gaps(ModuleContext("embervault.troubleshooter", "default", "EV-OP-11"), {
            "contract_version": 1,
            "evidence": [
                {"id": "verified", "state": "observed", "summary": "Synthetic check passed."},
                {"id": "runtime", "state": "unverified", "summary": "No runtime test performed."},
            ],
        })
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["gap_count"], 1)
        self.assertEqual(result.data["gaps"][0]["id"], "runtime")
        self.assertIn("approved offline or runtime validation", result.data["gaps"][0]["guidance"])

    def test_package_health_check_accepts_version_one_metadata(self):
        result = check_package_health(ModuleContext("embervault.troubleshooter", "default", "EV-OP-12"), {
            "id": "embervault.sample", "name": "Sample", "version": "1.0.0", "manifest_version": 1,
            "dependencies": ["embervault.sdk"],
        })
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["checks"]["manifest_version"], "passed")
        self.assertEqual(result.data["dependencies"], ["embervault.sdk"])

    def test_package_health_check_rejects_unknown_manifest(self):
        result = check_package_health(ModuleContext("embervault.troubleshooter", "default", "EV-OP-13"), {
            "id": "embervault.sample", "name": "Sample", "version": "1.0.0", "manifest_version": 2,
        })
        self.assertEqual(result.status, "blocked")

    def test_package_health_check_rejects_duplicate_dependencies(self):
        result = check_package_health(ModuleContext("embervault.troubleshooter", "default", "EV-OP-14"), {
            "id": "embervault.sample", "name": "Sample", "version": "1.0.0", "manifest_version": 1,
            "dependencies": ["embervault.sdk", "embervault.sdk"],
        })
        self.assertEqual(result.status, "blocked")


if __name__ == "__main__":
    unittest.main()
