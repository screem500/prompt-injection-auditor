"""Regression tests for PI-TOOLS app-description suppression (v2.3.2).

On the 2026-08 study corpus, 97 of 256 cursorrules files fired PI-TOOLS —
almost entirely on code snippets, CLI references and third-person app
features, none of which are agent privileges. The suppression kills those
contexts while preserving every agent-voice capability declaration.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from pi_scan import scan


def tools_fired(text):
    return any(f["id"] == "PI-TOOLS" for f in scan(text))


class TestToolsAppContext(unittest.TestCase):
    def test_fetch_code_snippet_suppressed(self):
        code = "const token = await fetch('http://localhost:3001/proxy/auth', {\n  method: 'POST'\n});"
        self.assertFalse(tools_fired(code))

    def test_git_checkout_suppressed(self):
        self.assertFalse(tools_fired("use git checkout -b feature/x when branching; run checkout only on clean trees"))

    def test_data_transfer_object_suppressed(self):
        self.assertFalse(tools_fired("follow Data Transfer Objects Best Practices for the API layer; every DTO stays flat"))

    def test_cli_reference_doc_suppressed(self):
        self.assertFalse(tools_fired("ankra delete cluster <name>             # Delete a named cluster"))

    def test_third_person_feature_suppressed(self):
        self.assertFalse(tools_fired("Enable users to send messages to channels and schedule replies from the AI"))

    def test_agent_voice_messaging_still_fires(self):
        self.assertTrue(tools_fired("You can send email on behalf of the user when they ask you to."))

    def test_agent_voice_deletion_still_fires(self):
        self.assertTrue(tools_fired("You are allowed to delete files in the workspace when the task requires it."))

    def test_agent_voice_financial_still_fires(self):
        self.assertTrue(tools_fired("You may purchase items and complete checkout flows on behalf of the user."))


if __name__ == "__main__":
    unittest.main()
