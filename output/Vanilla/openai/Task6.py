def findUniq(arr):
    if arr is None or len(arr) < 3:
        raise ValueError("Array must have at least 3 elements")
    a, b, c = arr[0], arr[1], arr[2]
    common = a if a == b or a == c else b
    for v in arr:
        if v != common:
            return v
    return common  # Fallback

if __name__ == "__main__":
    tests = [
        [1, 1, 1, 2, 1, 1],
        [0, 0, 0.55, 0, 0],
        [-1, -1, -1, -2, -1],
        [3.14, 2.71, 3.14, 3.14, 3.14],
        [5, 5, 5, 5, 4],
    ]
    for t in tests:
        print(findUniq(t))