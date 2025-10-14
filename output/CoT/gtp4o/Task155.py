# Chain-of-Through process:
# 1) Problem understanding: Implement heap sort that returns a new sorted list.
# 2) Security requirements: Do not mutate inputs; handle None and empty safely.
# 3) Secure coding generation: Use iterative heapify and safe index checks.
# 4) Code review: Ensured no in-place mutation, bounds-safe operations.
# 5) Secure code output: Final function with tests.

from typing import List, Optional

def heap_sort(arr: Optional[List[int]]) -> Optional[List[int]]:
    if arr is None:
        return None
    a = list(arr)  # Do not mutate input
    n = len(a)

    def heapify(size: int, i: int) -> None:
        while True:
            largest = i
            left = 2 * i + 1
            right = 2 * i + 2

            if left < size and a[left] > a[largest]:
                largest = left
            if right < size and a[right] > a[largest]:
                largest = right
            if largest != i:
                a[i], a[largest] = a[largest], a[i]
                i = largest
            else:
                break

    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(n, i)

    # Heap sort
    for i in range(n - 1, 0, -1):
        a[0], a[i] = a[i], a[0]
        heapify(i, 0)

    return a

def _print(arr):
    print(arr if arr is not None else "None")

if __name__ == "__main__":
    tests = [
        [4, 10, 3, 5, 1],
        [],
        [1],
        [5, -1, 3, -2, 0, 5, 5],
        [1000000000, -1000000000, 2_147_483_647, -2_147_483_648, 42],
    ]
    for idx, t in enumerate(tests, 1):
        sorted_t = heap_sort(t)
        print(f"Test {idx} input:  {t}")
        print(f"Test {idx} sorted: {sorted_t}")
        print()