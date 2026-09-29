"""
Default and custom pattern definitions for secret detection.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

DEFAULT_RULES = [
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api[_-]?key|apikey|app[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{8,})[\"']?",
        "description": "Matches generic API key assignments."
    },
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        "description": "Matches standard AWS Access Key ID strings."
    },
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[a-zA-Z0-9]{32,}",
        "description": "Matches OpenAI API secret key format."
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pous]_[a-zA-Z0-9]{36}",
        "description": "Matches GitHub Personal Access Tokens and OAuth tokens."
    },
    {
        "name": "Password Assignment",
        "pattern": r"(?i)(password|pass|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"']{4,})[\"']?",
        "description": "Matches password variable or key-value assignments."
    },
    {
        "name": "Secret Key",
        "pattern": r"(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{8,})[\"']?",
        "description": "Matches client secret or secret key variable definitions."
    },
    {
        "name": "Access Token",
        "pattern": r"(?i)(access[_-]?token|bearer[_-]?token|auth[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{8,})[\"']?",
        "description": "Matches access tokens and authorization bearer tokens."
    },
    {
        "name": "Private Key Header",
        "pattern": r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PRIVATE)\s+KEY-----",
        "description": "Matches standard PEM/SSH private key file headers."
    }
]


@dataclass
class SecretRule:
    """Represents a compiled secret detection rule."""
    name: str
    pattern: str
    compiled_regex: re.Pattern
    description: str = ""


class PatternLoader:
    """Loads and compiles detection rules from default list or custom JSON config."""

    @staticmethod
    def load_rules(config_path: Optional[str] = None) -> List[SecretRule]:
        rules_data = DEFAULT_RULES

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, dict) and "rules" in content:
                        rules_data = content["rules"]
                    elif isinstance(content, list):
                        rules_data = content
            except Exception:
                # Fallback to default rules if config loading fails
                pass

        compiled_rules: List[SecretRule] = []
        for rule_def in rules_data:
            name = rule_def.get("name", "Unknown Rule")
            pat_str = rule_def.get("pattern", "")
            desc = rule_def.get("description", "")

            if pat_str:
                try:
                    compiled = re.compile(pat_str)
                    compiled_rules.append(
                        SecretRule(
                            name=name,
                            pattern=pat_str,
                            compiled_regex=compiled,
                            description=desc
                        )
                    )
                except re.error:
                    # Skip invalid regex patterns gracefully
                    continue

        return compiled_rules
