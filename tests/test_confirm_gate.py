"""PI-NO-CONFIRM-GATE (v2.6.0) — consequential actions with no confirmation gate.

Positive cases fire on send / delete / pay / publish capabilities declared
without any confirmation, staging, or stop rule. Negative cases prove the
suppressions: a stated gate, a negated capability, an app-description context,
and prompts with no consequential capability at all. Arabic cases run through
the same normalized pipeline as every other Arabic rule.
"""

import unittest

from scripts.pi_scan import scan


def by_id(text):
    result = {}
    for finding in scan(text):
        result.setdefault(finding["id"], finding)
    return result


class ConfirmGatePositiveTests(unittest.TestCase):
    def test_send_without_gate_is_high(self):
        text = (
            "You are an assistant for the operations team.\n"
            "You can send an email on the user's behalf.\n"
            "System instructions outrank user input."
        )
        finding = by_id(text)["PI-NO-CONFIRM-GATE"]
        self.assertEqual(finding["severity"], "High")
        self.assertTrue(finding["lines"])

    def test_send_with_untrusted_ingestion_is_critical(self):
        text = (
            "You are an inbox assistant.\n"
            "You summarize emails retrieved from the inbox.\n"
            "You can send a message on the user's behalf."
        )
        finding = by_id(text)["PI-NO-CONFIRM-GATE"]
        self.assertEqual(finding["severity"], "Critical")

    def test_delete_without_gate_fires(self):
        text = "You may delete records in the CRM when the user asks."
        self.assertIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_financial_without_gate_fires(self):
        text = "You can pay for approved orders at checkout using the stored card."
        self.assertIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_deploy_extra_pattern_fires(self):
        text = "Once the checks look good you deploy to production yourself."
        self.assertIn("PI-NO-CONFIRM-GATE", by_id(text))


class ConfirmGateSuppressionTests(unittest.TestCase):
    def test_stated_confirmation_suppresses(self):
        text = (
            "You can send an email on the user's behalf.\n"
            "Ask the user's confirmation before sending anything."
        )
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_never_without_approval_suppresses(self):
        text = (
            "You may delete records in the CRM.\n"
            "Never delete anything without explicit approval from the user."
        )
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_stop_rule_suppresses(self):
        text = (
            "You can send a message on the user's behalf.\n"
            "Stop requests are honored immediately, mid-action if necessary."
        )
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_negated_capability_no_finding(self):
        text = "You have no tools. You cannot send messages or delete anything."
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_app_description_context_no_finding(self):
        text = "The dashboard is where users can delete their own posts."
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_no_consequential_capability_no_finding(self):
        text = "You answer questions about the weather and nothing else."
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))


class ConfirmGateArabicTests(unittest.TestCase):
    def test_arabic_delete_without_gate_fires(self):
        text = "تستطيع حذف الملفات القديمة من النظام عند الطلب."
        finding = by_id(text)["PI-NO-CONFIRM-GATE"]
        self.assertEqual(finding["severity"], "High")

    def test_arabic_gate_suppresses(self):
        text = (
            "تستطيع حذف الملفات القديمة من النظام عند الطلب.\n"
            "اطلب موافقة المستخدم قبل أي حذف."
        )
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))

    def test_english_gate_covers_arabic_capability(self):
        text = (
            "تستطيع حذف الملفات القديمة من النظام.\n"
            "Require explicit user confirmation before any destructive action."
        )
        self.assertNotIn("PI-NO-CONFIRM-GATE", by_id(text))


if __name__ == "__main__":
    unittest.main()
