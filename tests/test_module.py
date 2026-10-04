import unittest

from embervault_sdk import ModuleContext
from src.module import scan


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


if __name__ == "__main__":
    unittest.main()
