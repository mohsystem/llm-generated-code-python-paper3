import os
import re
import tempfile
import time
from typing import List


def binary_search(arr: List[int], target: int) -> int:
    if not isinstance(arr, list):
        return -1
    left = 0
    right = len(arr) - 1
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


def _sanitize_label(label: str) -> str:
    s = label if isinstance(label, str) else ""
    s = s[:128]
    return re.sub(r"[^A-Za-z0-9 _\-]", "_", s)


def write_execution_time_to_temp_file(nanos: int, label: str) -> str:
    safe_label = _sanitize_label(label)
    content = f"label={safe_label}\nexecution_time_ns={int(nanos)}\n"

    # Create a secure temporary file and restrict permissions
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, prefix="task87_", suffix=".tmp") as tf:
        path = tf.name
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass  # Best effort on non-POSIX systems
        tf.write(content)
        tf.flush()
        os.fsync(tf.fileno())
    return os.path.abspath(path)


def main() -> None:
    arrays = [
        [1, 3, 5, 7, 9],
        [2, 4, 6, 8, 10],
        [0],
        [-10, -5, 0, 5, 10, 15],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    ]
    targets = [7, 1, 0, 15, 11]

    start = time.perf_counter_ns()
    results = [binary_search(arr, tgt) for arr, tgt in zip(arrays, targets)]
    end = time.perf_counter_ns()
    total_nanos = end - start

    path = write_execution_time_to_temp_file(total_nanos, "total_run")
    print(f"Binary search results (indices): {results}")
    print(f"Execution time written to: {path}")


if __name__ == "__main__":
    main()