from typing import List

def find_outlier(arr: List[int]) -> int:
    if not isinstance(arr, list) or len(arr) < 3:
        raise ValueError("Input array must be a list with length >= 3.")
    for x in arr:
        if type(x) is not int:  # disallow non-int (including bool)
            raise ValueError("All elements must be integers.")
    even_count = 0
    for i in range(3):
        if arr[i] % 2 == 0:
            even_count += 1
    majority_even = even_count >= 2

    outlier = None
    mismatch_count = 0
    for v in arr:
        is_even = (v % 2 == 0)
        if is_even != majority_even:
            mismatch_count += 1
            outlier = v
            if mismatch_count > 1:
                break
    if mismatch_count != 1 or outlier is None:
        raise ValueError("Array does not contain exactly one parity outlier.")
    return outlier

def run_test(input_arr: List[int], expected: int) -> None:
    try:
        result = find_outlier(input_arr)
        print(f"Input: {input_arr} -> Outlier: {result} | Expected: {expected}")
    except ValueError as e:
        print(f"Input: {input_arr} -> Error: {e}")

if __name__ == "__main__":
    run_test([2, 4, 0, 100, 4, 11, 2602, 36], 11)
    run_test([160, 3, 1719, 19, 11, 13, -21], 160)
    run_test([1, 1, 2], 2)
    run_test([2, -6, 8, -10, -3], -3)
    run_test([3, 5, 7, 9, 2], 2)