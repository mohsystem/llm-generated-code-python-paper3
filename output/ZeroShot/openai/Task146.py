def find_missing(arr, n):
    if not isinstance(n, int) or n < 1 or arr is None or len(arr) != n - 1:
        return -1
    seen = [False] * (n + 1)
    xor_val = 0
    for i in range(1, n + 1):
        xor_val ^= i
    for v in arr:
        if not isinstance(v, int) or v < 1 or v > n:
            return -1
        if seen[v]:
            return -1
        seen[v] = True
        xor_val ^= v
    if xor_val < 1 or xor_val > n or seen[xor_val]:
        return -1
    return xor_val


def main():
    tests = [
        ([1, 2, 3, 5], 5),        # -> 4
        ([], 1),                  # -> 1
        ([7, 6, 5, 4, 3, 2], 7),  # -> 1
        ([1, 2, 2], 4),           # -> -1 (duplicate)
        ([0, 1, 2, 3, 4], 6),     # -> -1 (out of range)
    ]
    for arr, n in tests:
        print(find_missing(arr, n))


if __name__ == "__main__":
    main()