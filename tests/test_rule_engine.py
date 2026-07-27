import unittest

from pi_auditor.rules import MCP_GUARD_RULES, SHIELD_RULES, evaluate_rules, get_rules, score_rules
from pi_auditor.rules.models import PatternRule


class RuleRegistryTests(unittest.TestCase):
    def test_named_registry_returns_immutable_rules(self):
        self.assertIs(get_rules("shield"), SHIELD_RULES)
        self.assertIs(get_rules("mcp"), MCP_GUARD_RULES)
        self.assertIsInstance(SHIELD_RULES, tuple)

    def test_unknown_registry_name_fails_clearly(self):
        with self.assertRaisesRegex(KeyError, "unknown rule set"):
            get_rules("missing")

    def test_rule_ids_are_unique_per_ruleset(self):
        for rules in (SHIELD_RULES, MCP_GUARD_RULES):
            ids = [rule.id for rule in rules]
            self.assertEqual(len(ids), len(set(ids)))


class RuleEngineTests(unittest.TestCase):
    def test_channel_filtering(self):
        rule = PatternRule(
            id="TEST-1",
            pattern=r"danger",
            label="test",
            weight=40,
            channels=frozenset({"tool_response"}),
        )
        self.assertEqual(evaluate_rules("danger", [rule], channel="user_input"), [])
        self.assertEqual(len(evaluate_rules("danger", [rule], channel="tool_response")), 1)

    def test_scoring_is_capped(self):
        rules = tuple(
            PatternRule(id=f"T-{index}", pattern="x", label="x", weight=60)
            for index in range(2)
        )
        score, hits = score_rules("x", rules)
        self.assertEqual(score, 100)
        self.assertEqual(len(hits), 2)

    def test_hit_carries_match_location(self):
        rule = PatternRule(id="TEST-2", pattern="override", label="override", weight=60)
        hit = evaluate_rules("safe override text", [rule])[0]
        self.assertEqual((hit.start, hit.end), (5, 13))
        self.assertEqual(hit.matched_text, "override")


if __name__ == "__main__":
    unittest.main()
