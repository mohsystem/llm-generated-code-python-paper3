def find_odd(arr):
    if arr is None or len(arr) == 0:
        raise ValueError("Input array must not be null or empty")
    x = 0
    for v in arr:
        x ^= v
    return x

if __name__ == "__main__":
    tests = [
        [7],
        [0],
        [1, 1, 2],
        [0, 1, 0, 1, 0],
        [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]
    ]
    for i, t in enumerate(tests, 1):
        try:
            print(f"Test {i} result: {find_odd(t)}")
        except ValueError as e:
            print(f"Test {i} error: {e}")