def kth_largest(arr, k):
    if arr is None or k < 1 or k > len(arr):
        raise ValueError("Invalid k or array")
    return sorted(arr)[-k]

if __name__ == "__main__":
    tests = [
        ([3, 2, 1, 5, 6, 4], 2),
        ([3, 2, 3, 1, 2, 4, 5, 5, 6], 4),
        ([7], 1),
        ([-1, -2, -3, -4], 2),
        ([5, 5, 5, 5], 3),
    ]
    for arr, k in tests:
        print(kth_largest(arr, k))