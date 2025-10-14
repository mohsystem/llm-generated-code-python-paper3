from typing import List

def find_median_sorted_arrays(nums1: List[int], nums2: List[int]) -> float:
    a = [] if nums1 is None else nums1
    b = [] if nums2 is None else nums2

    if not a and not b:
        raise ValueError("Both input arrays are empty.")

    # Ensure a is the smaller array
    if len(a) > len(b):
        a, b = b, a

    m, n = len(a), len(b)
    low, high = 0, m
    half = (m + n + 1) // 2

    NEG_INF = -10**18
    POS_INF =  10**18

    while low <= high:
        i = (low + high) // 2
        j = half - i

        a_left  = NEG_INF if i == 0 else a[i - 1]
        a_right = POS_INF if i == m else a[i]
        b_left  = NEG_INF if j == 0 else b[j - 1]
        b_right = POS_INF if j == n else b[j]

        if a_left <= b_right and b_left <= a_right:
            if (m + n) % 2 == 0:
                return (max(a_left, b_left) + min(a_right, b_right)) / 2.0
            else:
                return float(max(a_left, b_left))
        elif a_left > b_right:
            high = i - 1
        else:
            low = i + 1

    raise ValueError("Input arrays must be sorted.")

def _run_test(a: List[int], b: List[int]) -> None:
    print(f"{find_median_sorted_arrays(a, b):.5f}")

if __name__ == "__main__":
    # 5 Test cases
    _run_test([1, 3], [2])                              # 2.00000
    _run_test([1, 2], [3, 4])                           # 2.50000
    _run_test([], [1])                                  # 1.00000
    _run_test([0, 0], [0, 0])                           # 0.00000
    _run_test([-1000000, -5, 0, 7], [-3, 2, 2, 1000000])  # 1.00000