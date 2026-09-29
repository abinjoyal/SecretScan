"""
Unit tests for Shannon Entropy calculation module.
"""

import pytest
from secretscan.entropy import calculate_entropy, is_high_entropy_secret


def test_calculate_entropy():
    # Low entropy strings (predictable/repeating)
    assert calculate_entropy("AAAAAAA") == 0.0
    assert calculate_entropy("abababab") == 1.0

    # High entropy strings (random hex/base64 keys)
    high_entropy_key = "d9f8a7e6b5c4d3e2f1a09876543210ab"
    score = calculate_entropy(high_entropy_key)
    assert score > 3.5


def test_is_high_entropy_secret():
    # Synthetic random secret key
    random_secret = "a8f7c9e0b1d2f3a4b5c6d7e8f9012345"
    is_secret, score = is_high_entropy_secret(random_secret)
    assert is_secret is True
    assert score >= 3.8

    # Simple plain text string (low entropy)
    normal_text = "this_is_a_normal_function_name"
    is_secret, _ = is_high_entropy_secret(normal_text)
    assert is_secret is False
