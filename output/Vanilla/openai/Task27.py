def find_outlier(arr):
    even_count = sum(1 for x in arr[:3] if (x & 1) == 0)
    majority_even = even_count >= 2
    for x in arr:
        if majority_even and (x & 1) == 1:
            return x
        if not majority_even and (x & 1) == 0:
            return x
    return None

if __name__ == "__main__":
    tests = [
        [2, 4, 0, 100, 4, 11, 2602, 36],
        [160, 3, 1719, 19, 11, 13, -21],
        [1, 1, 2],
        [2, 6, 8, 10, 3],
        [-2, -4, -6, -7, -8],
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} outlier: {find_outlier(t)}")