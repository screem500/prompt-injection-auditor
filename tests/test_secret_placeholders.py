"""Regression tests for PI-SECRET placeholder suppression (v2.3.2).

On the 2026-08 real-world study corpus, all 9 PI-SECRET firings were false
positives: placeholders, environment references and code references. The
suppression must kill those while keeping every real credential loud.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from pi_scan import scan


def secret_fired(text):
    return any(f["id"] == "PI-SECRET" for f in scan(text))


class TestSecretPlaceholders(unittest.TestCase):
    def test_env_reference_suppressed(self):
        self.assertFalse(secret_fired("const ai = new GoogleGenAI({apiKey: process.env.API_KEY});"))

    def test_named_placeholder_suppressed(self):
        self.assertFalse(secret_fired("BEE_CLIENT_SECRET=your_client_secret_here"))

    def test_self_describing_dummy_suppressed(self):
        self.assertFalse(secret_fired("Password: WrongPassword123 for the demo login"))

    def test_code_reference_suppressed(self):
        self.assertFalse(secret_fired('const token = localStorage.getItem("bearer_token");'))

    def test_real_generic_password_still_fires(self):
        self.assertTrue(secret_fired('db: password: "Xk9mQ2vLz8Pw3nR7tY5u"'))

    def test_real_openai_key_still_fires(self):
        self.assertTrue(secret_fired("key sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4 in prod"))

    def test_real_aws_key_still_fires(self):
        self.assertTrue(secret_fired("aws_access_key_id = AKIAJ7K2M9P4Q8R6S2T4"))


if __name__ == "__main__":
    unittest.main()
