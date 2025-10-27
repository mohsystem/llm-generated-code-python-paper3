def getValueFromArray(arr, n, idx):
    return arr[idx]

if __name__ == "__main__":
    import sys
    data = sys.stdin.read().strip().split()
    idx = int(data[0]) if data else 0

    tests = [
        [10, 20, 30, 40, 50],
        [1, 2, 3, 4],
        [7],
        [100, 200],
        [5, 4, 3, 2, 1, 0],
    ]

    test_idx = abs(idx) % len(tests)
    selected = tests[test_idx]
    n = len(selected)
    safe_idx = idx % n

    result = getValueFromArray(selected, n, safe_idx)
    raise SystemExit(result)