from typing import List

def find_outlier(arr: List[int]) -> int:
    if arr is None or len(arr) < 3:
        raise ValueError("Input array must have length >= 3")
    even_count = sum(1 for x in arr[:3] if (x & 1) == 0)
    majority_even = even_count >= 2
    for v in arr:
        is_even = (v & 1) == 0
        if is_even != majority_even:
            return v
    raise ValueError("No outlier found")

if __name__ == "__main__":
    tests = [
        [2, 4, 0, 100, 4, 11, 2602, 36],
        [160, 3, 1719, 19, 11, 13, -21],
        [-2, -4, -6, -8, -10, -3, -12],
        [1, 3, 5, 7, 8, 9, 11, 13],
        [42, 6, 8, 10, 12, 14, 16, 7]
    ]
    for t in tests:
        try:
            print(find_outlier(t))
        except Exception as e:
            print(f"Error: {e} for input {t}")