import time
import tempfile
import os
from typing import List

def binary_search(arr: List[int], target: int) -> int:
    if arr is None or len(arr) == 0:
        return -1
    low, high = 0, len(arr) - 1
    while low <= high:
        mid = low + ((high - low) >> 1)
        val = arr[mid]
        if val == target:
            return mid
        if val < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1

def measure_and_write_time(arr: List[int], target: int) -> str:
    start = time.perf_counter_ns()
    idx = binary_search(arr, target)
    elapsed = time.perf_counter_ns() - start
    # Use a secure named temporary file
    with tempfile.NamedTemporaryFile(prefix="task87_time_", suffix=".txt", delete=False, mode="w", encoding="utf-8") as tf:
        tf.write(f"elapsed_nanos={elapsed}, index={idx}\n")
        path = tf.name
    return path

if __name__ == "__main__":
    tests = []
    targets = []

    tests.append([1, 3, 5, 7, 9]); targets.append(7)
    tests.append([2, 4, 6, 8, 10]); targets.append(5)
    tests.append([]); targets.append(1)
    tests.append([-10, -5, 0, 5, 10]); targets.append(-10)
    tests.append(list(range(100000))); targets.append(12345)

    for i in range(5):
        idx = binary_search(tests[i], targets[i])
        path = measure_and_write_time(tests[i], targets[i])
        print(f"Test {i+1}: target={targets[i]}, index={idx}, timeFile={path}")