#!/usr/bin/env python3
import unittest
from pathlib import Path


class ValidateScriptTests(unittest.TestCase):
    def test_logtest_uses_runtime_jwt_and_not_redaction_placeholder(self):
        script = (Path(__file__).parents[1] / "scripts/validate.sh").read_text()
        self.assertIn('Authorization: Bearer ${TOK}', script)
        self.assertNotIn('Authorization: Bearer ***', script)


if __name__ == "__main__":
    unittest.main()
