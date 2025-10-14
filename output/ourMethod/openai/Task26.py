from typing import List, Sequence

def find_odd(arr: Sequence[int]) -> int:
    """
    Finds the one integer that appears an odd number of times using XOR.
    """
    if arr is None or len(arr) == 0:
        raise ValueError("Input array must not be None or empty.")
    result = 0
    for v in arr:
        if not isinstance(v, int):
            raise ValueError("All elements must be integers.")
        result ^= v
    return result

if __name__ == "__main__":
    tests: List[List[int]] = [
        [7],
        [0],
        [1, 1, 2],
        [0, 1, 0, 1, 0],
        [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1],
    ]
    for i, t in enumerate(tests, 1):
        try:
            res = find_odd(t)
            print(f"Test {i} input={t} result={res}")
        except ValueError as e:
            print(f"Test {i} error: {e}")