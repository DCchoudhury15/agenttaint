"""Tests for the AST fix-suggester."""

from __future__ import annotations

import unittest
from pathlib import Path

from fix_suggester.suggest import analyze_file, narrate
from sdk.destinations import DEST_EXTERNAL, DEST_LLM

SAMPLE = Path(__file__).resolve().parents[1] / "fix_suggester" / "sample_buggy_agent.py"


class TestFixSuggester(unittest.TestCase):
    def setUp(self):
        self.findings = analyze_file(SAMPLE)

    def test_finds_external_post(self):
        f = next((x for x in self.findings if x.call == "requests.post"), None)
        self.assertIsNotNone(f, "requests.post not flagged")
        self.assertEqual(f.destination, DEST_EXTERNAL)
        self.assertEqual(f.enclosing, "send_to_auditor")

    def test_finds_llm_create(self):
        f = next((x for x in self.findings if x.call == "openai.ChatCompletion.create"), None)
        self.assertIsNotNone(f, "openai create not flagged")
        self.assertEqual(f.destination, DEST_LLM)
        self.assertEqual(f.enclosing, "summarize_with_llm")

    def test_finds_module_level_put(self):
        f = next((x for x in self.findings if x.call == "requests.put"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f.enclosing, "<module>")

    def test_does_not_flag_safe_internal(self):
        # safe_internal_lookup has no egress sink -> no finding references it
        self.assertFalse(any(x.enclosing == "safe_internal_lookup" for x in self.findings))

    def test_fix_mentions_redact_payload(self):
        for f in self.findings:
            self.assertIn("redact_payload", f.fix)
            self.assertIn(f.destination.upper(), f.fix)

    def test_narrate_is_grounded(self):
        f = self.findings[0]
        text = narrate(f)
        self.assertIn(f.call, text)
        self.assertIn(f.destination, text)
        self.assertIn("redact_payload", text)


if __name__ == "__main__":
    unittest.main()