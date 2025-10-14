import sys

def _compute_lps_array(pattern: str) -> list[int]:
    """
    Computes the Longest Proper Prefix Suffix (LPS) array for KMP algorithm.
    """
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

def shortest_palindrome(s: str) -> str:
    """
    Finds the shortest palindrome by adding characters to the front of the string.
    """
    if not s or len(s) <= 1:
        return s

    reversed_s = s[::-1]
    temp = s + '#' + reversed_s
    
    lps = _compute_lps_array(temp)
    lps_length = lps[-1]

    suffix_to_add = s[lps_length:]
    prefix = suffix_to_add[::-1]

    return prefix + s

if __name__ == '__main__':
    test_cases = [
        ("aacecaaa", "aaacecaaa"),
        ("abcd", "dcbabcd"),
        ("aba", "aba"),
        ("", ""),
        ("a", "a")
    ]

    for i, (input_str, expected) in enumerate(test_cases):
        result = shortest_palindrome(input_str)
        print(f"Input: \"{input_str}\"")
        print(f"Output: \"{result}\"")
        print(f"Expected: \"{expected}\"")
        print(f"Test {i + 1} {'Passed' if result == expected else 'Failed'}")
        print()