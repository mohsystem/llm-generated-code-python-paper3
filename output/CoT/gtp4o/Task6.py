EPS = 1e-9

def _eq(a: float, b: float) -> bool:
    return abs(a - b) <= EPS

def findUniq(arr):
    if arr is None or len(arr) < 3:
        raise ValueError("Array must have at least 3 elements")
    if _eq(arr[0], arr[1]) or _eq(arr[0], arr[2]):
        majority = arr[0]
    else:
        majority = arr[1]
    for v in arr:
        if not _eq(v, majority):
            return v
    return float('nan')

if __name__ == "__main__":
    tests = [
        [1, 1, 1, 2, 1, 1],
        [0, 0, 0.55, 0, 0],
        [-2, -2, -2, -3, -2],
        [5, 6, 5, 5, 5],
        [7.7, 7.7, 7.7, 7.7, 8.8]
    ]
    for t in tests:
        print(findUniq(t))