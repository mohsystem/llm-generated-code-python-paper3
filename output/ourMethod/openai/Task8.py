from typing import List, Sequence

def find_missing_letter(arr: Sequence[str]) -> str:
    if arr is None or not isinstance(arr, (list, tuple)) or len(arr) < 2:
        raise ValueError("Invalid input: array must be a list/tuple with at least 2 letters.")

    first = arr[0]
    if not isinstance(first, str) or len(first) != 1 or not first.isalpha():
        raise ValueError("Invalid input: elements must be single alphabetic characters.")
    is_upper = first.isupper()

    prev_ord = ord(first)
    for idx, ch in enumerate(arr):
        if not isinstance(ch, str) or len(ch) != 1 or not ch.isalpha():
            raise ValueError(f"Invalid element at index {idx}: must be a single alphabetic character.")
        if ch.isupper() != is_upper:
            raise ValueError("Invalid input: all letters must be of the same case.")
        o = ord(ch)
        if idx > 0:
            if o <= prev_ord:
                raise ValueError("Invalid input: letters must be strictly increasing.")
            if o - prev_ord > 1:
                return chr(prev_ord + 1)
        prev_ord = o

    candidate = chr(ord(arr[0]) + len(arr))
    if candidate.isalpha() and (candidate.isupper() == is_upper):
        return candidate
    raise ValueError("Missing letter out of range.")

if __name__ == "__main__":
    tests: List[List[str]] = [
        ['a', 'b', 'c', 'd', 'f'],
        ['O', 'Q', 'R', 'S'],
        ['g', 'h', 'j', 'k'],
        ['A', 'B', 'C', 'E'],
        ['t', 'u', 'v', 'x'],
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {find_missing_letter(t)}")