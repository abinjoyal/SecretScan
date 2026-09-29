"""
Unit tests for SecretScan pattern rules and loader.
"""

import tempfile
import json
import pytest
from secretscan.patterns import PatternLoader


def test_default_rules_loaded():
    rules = PatternLoader.load_rules()
    assert len(rules) > 0
    rule_names = [r.name for r in rules]
    assert "Generic API Key" in rule_names
    assert "AWS Access Key ID" in rule_names
    assert "Password Assignment" in rule_names


def test_custom_json_rules_loading():
    custom_rules = {
        "rules": [
            {
                "name": "Custom Token Pattern",
                "pattern": r"CUSTOM_TOKEN_[A-Za-z0-9]{16}",
                "description": "Custom secret pattern."
            }
        ]
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(custom_rules, tmp)
        tmp_path = tmp.name

    rules = PatternLoader.load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].name == "Custom Token Pattern"
