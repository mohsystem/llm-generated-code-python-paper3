import string
from typing import Optional

def is_pangram(s: Optional[str]) -> bool:
    """
    Checks if a string is a pangram.
    A pangram is a sentence containing every letter of the English alphabet at least once.
    The check is case-insensitive and ignores numbers and punctuation.
    """
    if not isinstance(s, str):
        return False
        
    found_letters = {char for char in s.lower() if 'a' <= char <= 'z'}
    return len(found_letters) == 26

if __name__ == '__main__':
    test_cases = [
        "The quick brown fox jumps over the lazy dog",
        "This is not a pangram",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "A quick brown fox jumps over the lazy cat",
        ""
    ]
    
    expected_results = [
        True,
        False,
        True,
        False,
        False
    ]

    for i, (text, expected) in enumerate(zip(test_cases, expected_results)):
        result = is_pangram(text)
        print(f"Test Case {i + 1}: \"{text}\"")
        print(f"Is Pangram: {result}")
        print(f"Expected: {expected}")
        print(f"Result matches expected: {result == expected}")
        print()