# Python implementation
# Secure function with simple arithmetic, no external input usage.
from typing import List

def find_missing_letter(arr: List[str]) -> str:
    if arr is None or len(arr) < 2:
        raise ValueError("Invalid input: array must have at least 2 characters.")
    # Iterate through list and detect a gap > 1 in unicode code points
    for i in range(1, len(arr)):
        if ord(arr[i]) - ord(arr[i - 1]) != 1:
            return chr(ord(arr[i - 1]) + 1)
    # With valid input, we should always have returned above
    raise RuntimeError("No missing letter found.")

if __name__ == "__main__":
    tests = [
        ['a','b','c','d','f'],
        ['O','Q','R','S'],
        ['w','x','z'],
        ['A','B','C','E'],
        ['m','n','p','q','r']
    ]
    for idx, t in enumerate(tests, 1):
        print(f"Test {idx} missing letter: {find_missing_letter(t)}")