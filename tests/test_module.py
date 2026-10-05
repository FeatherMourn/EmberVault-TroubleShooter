import unittest

from embervault_sdk import ModuleContext
from cryptography.fernet import Fernet
from src.runtime import handle_history_request
from src.module import EncryptedReportHistory, ReportHistory, check_module_health, check_package_health, compare_recovery_health, compare_reports, execute_history_action, export_report, recovery_health_trend, review_evidence_gaps, review_recovery_evidence, scan, scan_evidence
import tempfile
from pathlib import Path


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

    def test_report_history_is_bounded_and_returns_copies(self):
        history = ReportHistory(limit=2)
        context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-HISTORY")
        for title in ("one", "two", "three"):
            history.add(export_report(scan(context, [{"id": title, "title": title, "severity": "info"}])))
        reports = history.list()
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["data"]["findings"][0]["id"], "two")
        reports[0]["data"]["findings"].clear()
        self.assertEqual(len(history.list()[0]["data"]["findings"]), 1)
        self.assertEqual(history.compare_latest()["added"], ["three"])

    def test_report_history_rejects_non_read_only_report(self):
        history = ReportHistory()
        with self.assertRaises(ValueError):
            history.add({"report_version": 1, "data": {"findings": []},
                         "read_only": False, "mutates_workspace": True})

    def test_encrypted_report_history_round_trips_sanitized_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports.enc"
            key = Fernet.generate_key()
            context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-ENCRYPTED")
            history = EncryptedReportHistory(path, key, limit=2)
            history.add(export_report(scan(context, [{"id": "one", "title": "One", "severity": "info"}])))
            history.save()
            self.assertTrue(path.is_file())
            restored = EncryptedReportHistory(path, key, limit=2)
            restored.load()
            self.assertEqual(restored.list()[0]["data"]["findings"][0]["id"], "one")

    def test_encrypted_report_history_rejects_wrong_key(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports.enc"
            first = EncryptedReportHistory(path, Fernet.generate_key())
            first.save()
            wrong = EncryptedReportHistory(path, Fernet.generate_key())
            with self.assertRaises(ValueError):
                wrong.load()

    def test_encrypted_report_history_delete_removes_persisted_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports.enc"
            key = Fernet.generate_key()
            history = EncryptedReportHistory(path, key)
            history.add(export_report(scan(ModuleContext("embervault.troubleshooter", "default", "EV-OP-DELETE"),
                                          [{"id": "one", "title": "One", "severity": "info"}])))
            history.save()
            history.delete()
            self.assertFalse(path.exists())
            self.assertEqual(history.list(), [])

    def test_encrypted_report_history_ignores_interrupted_temp_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports.enc"
            path.with_name("reports.enc.tmp").write_bytes(b"incomplete")
            history = EncryptedReportHistory(path, Fernet.generate_key())
            history.load()
            self.assertEqual(history.list(), [])

    def test_encrypted_report_history_rejects_corrupt_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports.enc"
            key = Fernet.generate_key()
            path.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                EncryptedReportHistory(path, key).load()

    def test_history_execution_requires_approval_and_targets_store_only(self):
        with tempfile.TemporaryDirectory() as temp:
            history = EncryptedReportHistory(Path(temp) / "reports.enc", Fernet.generate_key())
            context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-EXECUTE")
            blocked = execute_history_action(context, history, "save", False)
            self.assertEqual(blocked.status, "blocked")
            ready = execute_history_action(context, history, "save", True)
            self.assertEqual(ready.status, "ready")
            self.assertEqual(ready.data["target"], "encrypted-diagnostic-report-store")

    def test_packaged_runtime_resolves_key_by_reference_only(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Fernet.generate_key()
            context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-RUNTIME")
            result = handle_history_request(context, {
                "contract_version": 1, "action": "save", "approved": True,
                "store_path": str(Path(temp) / "reports.enc"), "key_reference": "profile-key",
            }, EncryptedReportHistory, lambda reference: key if reference == "profile-key" else (_ for _ in ()).throw(KeyError(reference)))
            self.assertEqual(result.status, "ready")

    def test_packaged_runtime_rejects_missing_key_reference(self):
        context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-RUNTIME-2")
        result = handle_history_request(context, {
            "contract_version": 1, "action": "save", "approved": True, "store_path": "reports.enc",
        }, EncryptedReportHistory, lambda _: Fernet.generate_key())
        self.assertEqual(result.status, "blocked")

    def test_packaged_runtime_handles_read_only_recovery_trend(self):
        context = ModuleContext("embervault.troubleshooter", "default", "EV-OP-TREND")
        result = handle_history_request(context, {
            "contract_version": 1, "operation": "recovery-trend", "read_only": True,
            "reviews": [{"recovery_schema_version": 1, "rollback_ready": True, "findings": []}],
        }, EncryptedReportHistory, lambda _: Fernet.generate_key())
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.data["review_count"], 1)

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

    def test_recovery_evidence_reports_backup_and_compatibility_gaps(self):
        result = review_recovery_evidence(ModuleContext("embervault.troubleshooter", "default", "EV-OP-RECOVERY"), {
            "schema_version": 1, "operation_id": "recovery-1", "validated": False, "mutated_files": False,
            "compatibility": "unknown", "sources": {
                "source_backup": {"state": "ready"}, "current_state_backup": {"state": "blocked"},
                "restored_target": {"state": "ready"},
            },
        })
        self.assertEqual(result.status, "ready")
        self.assertFalse(result.data["rollback_ready"])
        self.assertGreaterEqual(result.data["finding_count"], 2)

    def test_recovery_evidence_ready_fixture_is_rollback_ready(self):
        result = review_recovery_evidence(ModuleContext("embervault.troubleshooter", "default", "EV-OP-RECOVERY-2"), {
            "schema_version": 1, "operation_id": "recovery-2", "validated": True, "mutated_files": False,
            "compatibility": "supported", "sources": {
                "source_backup": {"state": "ready"}, "current_state_backup": {"state": "ready"},
                "restored_target": {"state": "ready"},
            },
        })
        self.assertEqual(result.status, "ready")
        self.assertTrue(result.data["rollback_ready"])

    def test_recovery_health_comparison_tracks_readiness_and_gaps(self):
        previous = {"recovery_schema_version": 1, "rollback_ready": False,
                    "findings": [{"id": "backup", "status": "blocked"}]}
        current = {"recovery_schema_version": 1, "rollback_ready": True,
                   "findings": [{"id": "compatibility", "status": "unsupported"}]}
        comparison = compare_recovery_health(previous, current)
        self.assertTrue(comparison["rollback_ready_changed"])
        self.assertTrue(comparison["rollback_ready_after"])
        self.assertEqual(comparison["new_gaps"], ["compatibility"])
        self.assertEqual(comparison["resolved_gaps"], ["backup"])

    def test_recovery_health_trend_reports_recurring_gaps_and_transitions(self):
        trend = recovery_health_trend([
            {"recovery_schema_version": 1, "rollback_ready": False, "findings": [{"id": "backup"}]},
            {"recovery_schema_version": 1, "rollback_ready": True, "findings": [{"id": "backup"}, {"id": "compatibility"}]},
            {"recovery_schema_version": 1, "rollback_ready": False, "findings": [{"id": "backup"}]},
        ])
        self.assertEqual(trend["review_count"], 3)
        self.assertEqual(trend["rollback_transitions"], 2)
        self.assertEqual(trend["recurring_gaps"], ["backup"])
        self.assertTrue(trend["read_only"])

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
