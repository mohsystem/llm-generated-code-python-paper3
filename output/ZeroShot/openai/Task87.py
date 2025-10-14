import os
import tempfile
import time
from typing import List

def binary_search(arr: List[int], target: int) -> int:
    if arr is None:
        return -1
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = left + ((right - left) // 2)
        val = arr[mid]
        if val == target:
            return mid
        if val < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1

def write_execution_time_to_temp(nanos: int) -> str:
    fd, path = tempfile.mkstemp(prefix="task87_bsearch_", suffix=".tmp", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(str(nanos) + "\n")
        return path
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise

def main():
    start = time.perf_counter_ns()

    print("Test 1:", binary_search([1,3,5,7,9], 7))          # expected 3
    print("Test 2:", binary_search([], 1))                   # expected -1
    print("Test 3:", binary_search([-10,-3,0,0,5,8], 0))     # expected 2 or 3
    print("Test 4:", binary_search([1], 1))                  # expected 0
    print("Test 5:", binary_search([2,4,6,8,10,12,14,16], 15)) # expected -1

    end = time.perf_counter_ns()
    elapsed = end - start
    try:
        path = write_execution_time_to_temp(elapsed)
        print("Execution time (ns) written to:", os.path.abspath(path))
    except Exception as e:
        print("Failed to write execution time:", str(e))

if __name__ == "__main__":
    main()