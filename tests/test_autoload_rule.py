"""Tests for the PI-AUTOLOAD-CONFIG rule."""

import unittest

from scripts.pi_scan import scan


def by_id(text):
    result = {}
    for finding in scan(text):
        result.setdefault(finding["id"], finding)
    return result


class AutoloadConfigRuleTests(unittest.TestCase):

    def test_autoload_without_trust_gate_is_flagged(self):
        text = (
            "You are a coding assistant.\n"
            "On startup you automatically read AGENTS.md from the project root."
        )
        self.assertIn("PI-AUTOLOAD-CONFIG", by_id(text))

    def test_autoload_with_exec_is_critical(self):
        text = (
            "You are a coding assistant with a bash tool.\n"
            "On startup you automatically read .cursorrules from the repo root."
        )
        self.assertEqual(
            by_id(text)["PI-AUTOLOAD-CONFIG"]["severity"], "Critical")

    def test_autoload_without_exec_is_high(self):
        text = (
            "You summarise documents for the user.\n"
            "When you open the project you automatically load CLAUDE.md."
        )
        self.assertEqual(
            by_id(text)["PI-AUTOLOAD-CONFIG"]["severity"], "High")

    def test_trust_gate_suppresses_the_finding(self):
        text = (
            "You are a coding assistant with a bash tool.\n"
            "On startup you automatically read AGENTS.md from the project root, "
            "but only after the user has approved the workspace trust dialog."
        )
        self.assertNotIn("PI-AUTOLOAD-CONFIG", by_id(text))

    def test_config_file_alone_is_not_flagged(self):
        text = "Your operating instructions live in CLAUDE.md."
        self.assertNotIn("PI-AUTOLOAD-CONFIG", by_id(text))

    def test_trigger_alone_is_not_flagged(self):
        text = "You automatically load the user's saved preferences at session start."
        self.assertNotIn("PI-AUTOLOAD-CONFIG", by_id(text))

    def test_finding_maps_to_checklist_28(self):
        text = (
            "You are a coding assistant.\n"
            "On startup you automatically read AGENTS.md from the project root."
        )
        self.assertIn("#28", by_id(text)["PI-AUTOLOAD-CONFIG"]["fix"])

    def test_arabic_autoload_is_flagged(self):
        text = (
            "انت مساعد برمجي.\n"
            "تقرا ملف الاعداد .cursorrules عند فتح المستودع تلقائيا."
        )
        self.assertIn("PI-AUTOLOAD-CONFIG", by_id(text))


if __name__ == "__main__":
    unittest.main()
