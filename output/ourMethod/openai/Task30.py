from typing import Set

def longest(s1: str, s2: str) -> str:
    if not isinstance(s1, str) or not isinstance(s2, str):
        raise ValueError("Inputs must be strings.")
    combined = s1 + s2
    if any((c < 'a' or c > 'z') for c in combined):
        raise ValueError("Inputs must contain only lowercase a-z letters.")
    distinct: Set[str] = set(combined)
    return "".join(sorted(distinct))

if __name__ == "__main__":
    tests = [
        ("xyaabbbccccdefww", "xxxxyyyyabklmopq"),
        ("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("abc", "def"),
        ("", "abcxyz"),
        ("Abc", "def"),  # invalid test case
    ]
    for i, (a, b) in enumerate(tests, 1):
        try:
            res = longest(a, b)
            print(f'Test {i}: longest("{a}", "{b}") -> "{res}"')
        except ValueError as e:
            print(f'Test {i}: longest("{a}", "{b}") -> Error: {e}')