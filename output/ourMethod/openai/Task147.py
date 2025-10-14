from typing import List
import heapq

def kth_largest(arr: List[int], k: int) -> int:
    if not isinstance(arr, list):
        raise ValueError("Invalid input: arr must be a list of integers.")
    if any(not isinstance(x, int) for x in arr):
        raise ValueError("Invalid input: all elements of arr must be integers.")
    if not isinstance(k, int):
        raise ValueError("Invalid input: k must be an integer.")
    if len(arr) == 0:
        raise ValueError("Invalid input: array is empty.")
    if k < 1 or k > len(arr):
        raise ValueError("Invalid input: k out of range.")

    min_heap: List[int] = []
    for v in arr:
        if len(min_heap) < k:
            heapq.heappush(min_heap, v)
        else:
            if v > min_heap[0]:
                heapq.heapreplace(min_heap, v)
    if len(min_heap) != k:
        raise RuntimeError("Unexpected error: heap size mismatch.")
    return min_heap[0]

def _run_test(arr: List[int], k: int) -> None:
    try:
        result = kth_largest(arr, k)
        print(f"k={k}, result={result}")
    except (ValueError, RuntimeError) as ex:
        print(f"k={k}, error={str(ex)}")

if __name__ == "__main__":
    _run_test([3, 2, 1, 5, 6, 4], 2)            # expected 5
    _run_test([7, 10, 4, 3, 20, 15], 3)         # expected 10
    _run_test([-1, -2, -3, -4], 1)              # expected -1
    _run_test([5, 5, 5, 5], 2)                  # expected 5
    _run_test([1, 23, 12, 9, 30, 2, 50], 4)     # expected 12
    # Example invalid test (k out of range)
    _run_test([1], 2)                           # error