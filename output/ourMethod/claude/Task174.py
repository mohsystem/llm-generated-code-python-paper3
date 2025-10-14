
from typing import List


def shortest_palindrome(s: str) -> str:
    """Find the shortest palindrome by adding characters in front of s."""
    # Input validation
    if s is None:
        raise ValueError("Input string cannot be None")
    
    # Validate length constraint
    if len(s) > 50000:
        raise ValueError("Input string length exceeds maximum allowed (50000)")
    
    # Validate that string contains only lowercase English letters
    for c in s:
        if not ('a' <= c <= 'z'):
            raise ValueError("Input string must contain only lowercase English letters")
    
    if not s:
        return ""
    
    # Find the longest palindrome prefix using KMP
    rev = s[::-1]
    combined = s + "#" + rev
    
    lps = compute_lps(combined)
    longest_palindrome_prefix = lps[-1]
    
    # Add the suffix in reverse to the front
    suffix = s[longest_palindrome_prefix:]
    prefix = suffix[::-1]
    
    return prefix + s


def compute_lps(pattern: str) -> List[int]:
    """Compute the Longest Prefix Suffix array for KMP algorithm."""
    n = len(pattern)
    lps = [0] * n
    length = 0
    i = 1
    
    while i < n:
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                length = lps[length - 1]
            else:
                lps[i] = 0
                i += 1
    
    return lps


def main() -> None:
    test_cases = ["aacecaaa", "abcd", "", "a", "racecar"]
    
    for test_case in test_cases:
        print(f'Input: "{test_case}"')
        print(f'Output: "{shortest_palindrome(test_case)}"')
        print()


if __name__ == "__main__":
    main()
