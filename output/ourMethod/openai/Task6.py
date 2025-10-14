from typing import List

def find_uniq(arr: List[float]) -> float:
    if arr is None or len(arr) < 3:
        raise ValueError("Array must contain at least 3 numbers.")
    a, b, c = arr[0], arr[1], arr[2]
    common = a if (a == b or a == c) else b
    for v in arr:
        if v != common:
            return v
    raise ValueError("No unique value found.")

if __name__ == "__main__":
    tests: List[List[float]] = [
        [1, 1, 1, 2, 1, 1],
        [0, 0, 0.55, 0, 0],
        [3, 3, 4, 3, 3, 3],
        [9, 8, 8, 8, 8, 8],
        [-1, -1, -1, -2, -1, -1],
    ]
    for t in tests:
        print(find_uniq(t))