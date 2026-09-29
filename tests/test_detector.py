"""
Unit tests for SecretScan detector module.
"""

import pytest
from secretscan.detector import SecretDetector


def test_detector_api_key():
    detector = SecretDetector()
    matches = detector.scan_line("api_key = 'abcdef1234567890'", line_number=10, file_path="config.py")

    assert len(matches) >= 1
    match = matches[0]
    assert match.line_number == 10
    assert match.file_path == "config.py"
    assert match.secret_type == "Generic API Key"
    assert match.masked_value != "abcdef1234567890"  # Ensure raw secret is not returned unmasked


def test_detector_password_assignment():
    detector = SecretDetector()
    matches = detector.scan_line("password = 'my_super_secret_passwd_999'", line_number=5, file_path=".env")

    assert len(matches) >= 1
    match = [m for m in matches if m.secret_type == "Password Assignment"][0]
    assert match.line_number == 5
    assert match.file_path == ".env"


def test_detector_ignore_placeholders():
    detector = SecretDetector()
    matches = detector.scan_line("API_KEY = 'your_api_key'", line_number=1, file_path="template.py")

    assert len(matches) == 0  # Should skip common placeholder


def test_detector_no_matches_on_clean_line():
    detector = SecretDetector()
    matches = detector.scan_line("def add(a, b):\n    return a + b", line_number=2, file_path="math.py")

    assert len(matches) == 0
