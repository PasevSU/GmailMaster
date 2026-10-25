import json
import tempfile
import unittest
from pathlib import Path
from custom_components.pasevsu_gmail_rules.rules_engine import load_rules

class RuleValidationTests(unittest.TestCase):
    def test_rejects_nonboolean_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"rules.json"
            path.write_text(json.dumps({"filter":[{"query":"from:example.com","move":"false"}]}))
            with self.assertRaises(ValueError):load_rules(path)
