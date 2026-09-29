"""
Core detector logic for analyzing source code lines, matching secret patterns, and evaluating Shannon Entropy.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from secretscan.patterns import SecretRule, PatternLoader
from secretscan.utils import mask_secret
from secretscan.entropy import is_high_entropy_secret

# List of common placeholders to avoid false positives on example/template files
COMMON_PLACEHOLDERS = {
    "your_api_key", "your_secret_key", "your_password", "xxxxxxxx",
    "12345678", "abcdefgh", "sample_key", "example_token", "change_me"
}


@dataclass
class SecretMatch:
    """Represents a potential secret detection finding."""
    file_path: str
    line_number: int
    secret_type: str
    masked_value: str
    line_snippet: str


class SecretDetector:
    """Scans code lines using defined detection rules and entropy analysis."""

    def __init__(
        self,
        rules: Optional[List[SecretRule]] = None,
        config_path: Optional[str] = None,
        enable_entropy: bool = True
    ):
        if rules is not None:
            self.rules = rules
        else:
            self.rules = PatternLoader.load_rules(config_path)
        self.enable_entropy = enable_entropy

    def scan_line(self, line: str, line_number: int, file_path: str) -> List[SecretMatch]:
        """Scans a single line of text for potential secrets via regex and entropy."""
        matches: List[SecretMatch] = []
        clean_line = line.strip()

        if not clean_line:
            return matches

        # 1. Regex Pattern Matching
        matched_tokens = set()
        for rule in self.rules:
            for regex_match in rule.compiled_regex.finditer(clean_line):
                groups = regex_match.groups()
                detected_val = groups[-1] if groups else regex_match.group(0)

                if detected_val.lower().strip() in COMMON_PLACEHOLDERS:
                    continue

                matched_tokens.add(detected_val)
                masked = mask_secret(detected_val)
                matches.append(
                    SecretMatch(
                        file_path=file_path,
                        line_number=line_number,
                        secret_type=rule.name,
                        masked_value=masked,
                        line_snippet=clean_line[:100]
                    )
                )

        # 2. Shannon Entropy Analysis (for assigned string literals)
        if self.enable_entropy:
            # Extract string literal assignments e.g. var = 'xyz...' or key: "abc..."
            string_literals = re.findall(r"[\"']([A-Za-z0-9_\-\.\=\/+]{16,})[\"']", clean_line)
            for token in string_literals:
                if token in matched_tokens or token.lower().strip() in COMMON_PLACEHOLDERS:
                    continue

                is_entropy_secret, score = is_high_entropy_secret(token)
                if is_entropy_secret:
                    masked = mask_secret(token)
                    matches.append(
                        SecretMatch(
                            file_path=file_path,
                            line_number=line_number,
                            secret_type=f"High Entropy Secret (Score: {score:.2f})",
                            masked_value=masked,
                            line_snippet=clean_line[:100]
                        )
                    )

        return matches
