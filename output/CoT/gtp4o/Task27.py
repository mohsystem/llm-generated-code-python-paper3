from typing import List

def find_outlier(arr: List[int]) -> int:
    if arr is None or len(arr) < 3:
        raise ValueError("Input array must have length >= 3")
    odd_count = 0
    for x in arr[:3]:
        if (x & 1) != 0:
            odd_count += 1
    majority_odd = odd_count >= 2
    for v in arr:
        if ((v & 1) != 0) != majority_odd:
            return v
    raise ValueError("No outlier found")

if __name__ == "__main__":
    tests = [
        [2, 4, 0, 100, 4, 11, 2602, 36],
        [160, 3, 1719, 19, 11, 13, -21],
        [3, 5, 7, 9, 2, 11, 13],
        [2, 4, 6, 8, 10, 3, 12],
        [-2, -4, -6, -8, -11, -12]
    ]
    for t in tests:
        print(find_outlier(t))