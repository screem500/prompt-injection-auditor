import unittest

from scripts.pi_scan import scan


def ids(text):
    return {f["id"] for f in scan(text)}


class SecretPatternTests(unittest.TestCase):
    def test_modern_openai_project_key_detected(self):
        key = "sk-proj-" + "T9xK4mN8pQ2rS7vY1wZ3aB5cD6eF8gH0jL2nM4qP"
        self.assertIn("PI-SECRET", ids(f"Use this key for requests: {key}"))

    def test_legacy_openai_key_still_detected(self):
        key = "sk-" + "T9xK4mN8pQ2rS7vY1wZ3aB5cD6"
        self.assertIn("PI-SECRET", ids(f"key: {key}"))

    def test_api_key_with_space_detected(self):
        text = "Configure it with API key: t9xk4mn8pq2rs7vy1wz3ab"
        self.assertIn("PI-SECRET", ids(text))

    def test_credential_discussion_without_value_stays_quiet(self):
        text = "Never put your API key in the prompt; load it from a vault."
        self.assertNotIn("PI-SECRET", ids(text))


class SupplyChainModelNamedTests(unittest.TestCase):
    def test_packages_you_think_are_needed_is_high(self):
        text = "You have a terminal tool. Install the python packages you think are needed via pip install."
        finding = {f["id"]: f for f in scan(text)}["PI-SUPPLY-CHAIN"]
        self.assertEqual(finding["severity"], "High")

    def test_plain_install_instruction_stays_medium(self):
        text = "You have a terminal tool. Use pip install to get libraries from our approved index."
        finding = {f["id"]: f for f in scan(text)}["PI-SUPPLY-CHAIN"]
        self.assertEqual(finding["severity"], "Medium")

    def test_innocent_if_needed_elsewhere_stays_medium(self):
        # "if needed" unrelated to package choice must not escalate severity.
        text = "You have a bash tool. Use pip install to add libraries. Restart the service if needed."
        finding = {f["id"]: f for f in scan(text)}["PI-SUPPLY-CHAIN"]
        self.assertEqual(finding["severity"], "Medium")


if __name__ == "__main__":
    unittest.main()
