# Chain-of-Through process:
# 1) Problem understanding: Merge two sorted integer arrays into a single sorted array.
# 2) Security requirements: Handle None inputs; avoid side effects on inputs; deterministic merging.
# 3) Secure coding generation: Two-pointer merge; avoid unsafe operations.
# 4) Code review: Checked loops, indices, and edge cases.
# 5) Secure code output: Clean, robust, and self-contained.

from typing import List, Optional

def merge_sorted_arrays(a: Optional[List[int]], b: Optional[List[int]]) -> List[int]:
    # Defensive handling for None
    a = list(a) if a is not None else []
    b = list(b) if b is not None else []

    i, j = 0, 0
    result: List[int] = []

    # Merge using two-pointer technique; stable behavior
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            result.append(a[i])
            i += 1
        else:
            result.append(b[j])
            j += 1

    # Append remaining elements
    if i < len(a):
        result.extend(a[i:])
    if j < len(b):
        result.extend(b[j:])

    return result

def _print_array(arr: List[int]) -> None:
    print("[" + ", ".join(str(x) for x in arr) + "]")

if __name__ == "__main__":
    # 5 test cases
    tests_a = [
        [1, 3, 5],
        [0, 2, 2, 2],
        [],
        [-5, -3, 0, 4],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    ]
    tests_b = [
        [2, 4, 6],
        [1, 3, 5, 7],
        [],
        [-6, -4, -1, 2],
        [],
    ]

    for t in range(5):
        merged = merge_sorted_arrays(tests_a[t], tests_b[t])
        _print_array(merged)