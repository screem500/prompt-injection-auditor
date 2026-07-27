import unittest

from pi_auditor.languages import get_language_pack
from pi_auditor.rules.registry import SHIELD_RULES, MCP_GUARD_RULES


class LanguageAssetMigrationTests(unittest.TestCase):
    def test_english_pack_owns_static_and_runtime_assets(self):
        pack = get_language_pack("en")
        required = {
            "secret_patterns", "hierarchy_patterns", "nondisclosure_patterns",
            "tool_risk_keywords", "ingest_keywords", "mcp_present_patterns",
            "memory_patterns", "supply_chain_fetch_patterns",
            "shield_pattern_tuples", "mcp_pattern_tuples",
        }
        self.assertTrue(required.issubset(pack.capabilities))
        self.assertGreater(len(pack.attack_rules), 0)
        self.assertGreater(len(pack.get("shield_pattern_tuples")), 0)
        self.assertGreater(len(pack.get("mcp_pattern_tuples")), 0)

    def test_arabic_pack_owns_static_and_runtime_assets(self):
        pack = get_language_pack("ar")
        required = {
            "hierarchy_patterns", "nondisclosure_patterns", "tool_risk_keywords",
            "ingest_keywords", "mcp_present_patterns", "memory_patterns",
            "supply_chain_fetch_patterns",
        }
        self.assertTrue(required.issubset(pack.capabilities))
        self.assertGreater(len(pack.attack_rules), 0)

    def test_compiled_runtime_rules_come_from_english_pack(self):
        pack = get_language_pack("en")
        self.assertEqual(len(SHIELD_RULES), len(pack.get("shield_pattern_tuples")))
        self.assertEqual(len(MCP_GUARD_RULES), len(pack.get("mcp_pattern_tuples")))


if __name__ == "__main__":
    unittest.main()
