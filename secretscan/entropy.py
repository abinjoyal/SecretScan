"""
Shannon Entropy calculation engine for detecting high-entropy random secret strings.
"""

import math
from typing import Tuple


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string.
    Entropy measures randomness: higher values indicate more random/unpredictable strings.
    """
    if not text:
        return 0.0

    entropy = 0.0
    text_len = len(text)
    char_counts = {}

    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        probability = count / text_len
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def is_high_entropy_secret(text: str, threshold: float = 3.8, min_length: int = 16) -> Tuple[bool, float]:
    """
    Determines whether a string candidate exhibits high Shannon Entropy typical of API keys/secrets.
    Returns (is_secret, entropy_score).
    """
    clean_text = text.strip("'\" \t\r\n")

    # Skip strings with spaces or shorter than min_length
    if len(clean_text) < min_length or " " in clean_text:
        return False, 0.0

    # Skip common code words / URL components
    if clean_text.startswith("http://") or clean_text.startswith("https://"):
        return False, 0.0

    score = calculate_entropy(clean_text)
    if score >= threshold:
        return True, score

    return False, score
