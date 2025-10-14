from typing import List

def find_missing_number(arr: List[int], n: int) -> int:
    """
    Returns the missing number in the range [1..n] given an array of length n-1 with unique integers in that range.
    Returns 0 if the input is invalid (e.g., wrong length, out-of-range values, duplicates, or n < 1).
    """
    if not isinstance(n, int) or n < 1 or arr is None or len(arr) != n - 1:
        return 0
    seen = [False] * (n + 1)  # index 0 unused
    xor_arr = 0
    for v in arr:
        if not isinstance(v, int) or v < 1 or v > n:
            return 0
        if seen[v]:
            return 0  # duplicate
        seen[v] = True
        xor_arr ^= v
    xor_all = 0
    for i in range(1, n + 1):
        xor_all ^= i
    missing = xor_all ^ xor_arr
    if missing < 1 or missing > n or seen[missing]:
        return 0
    return missing

if __name__ == "__main__":
    # Test case 1
    print("Missing (n=5):", find_missing_number([1, 2, 3, 5], 5))  # 4

    # Test case 2
    print("Missing (n=1):", find_missing_number([], 1))  # 1

    # Test case 3
    print("Missing (n=3):", find_missing_number([2, 3], 3))  # 1

    # Test case 4
    print("Missing (n=10):", find_missing_number([1, 2, 3, 4, 5, 6, 8, 9, 10], 10))  # 7

    # Test case 5 (invalid: length mismatch)
    print("Missing (invalid n=5, len=5):", find_missing_number([1, 2, 3, 4, 5], 5))  # 0