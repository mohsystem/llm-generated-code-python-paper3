import time
import tempfile

def binary_search(arr, target):
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        if arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

if __name__ == "__main__":
    start = time.perf_counter()

    tests = [
        ([1, 3, 5, 7, 9], 7),
        ([1, 3, 5, 7, 9], 2),
        ([], 1),
        ([5], 5),
        ([-10, -3, 0, 5, 5, 9, 12], 5),
    ]
    results = [binary_search(a, t) for a, t in tests]

    for i, r in enumerate(results, 1):
        print(f"Test{i} index: {r}")

    elapsed = time.perf_counter() - start
    with tempfile.NamedTemporaryFile(delete=False, prefix="Task87_", suffix=".tmp", mode="w", encoding="utf-8") as f:
        f.write(f"elapsed_seconds={elapsed}\nelapsed_millis={elapsed*1000.0}\n")
        path = f.name
    print("Wrote timing to:", path)