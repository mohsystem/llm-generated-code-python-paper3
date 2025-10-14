from typing import List, Sequence

MAX_LEN = 1_000_000

def heap_sort(data: Sequence[int]) -> List[int]:
    if data is None:
        raise ValueError("Input must not be None.")
    if not isinstance(data, (list, tuple)):
        raise ValueError("Input must be a list or tuple of integers.")
    n = len(data)
    if n < 0 or n > MAX_LEN:
        raise ValueError("Invalid input length.")
    for i, x in enumerate(data):
        if not isinstance(x, int):
            raise ValueError(f"All elements must be integers. Invalid at index {i}.")

    arr: List[int] = list(data)

    def sift_down(start: int, heap_size: int) -> None:
        root = start
        while True:
            left = 2 * root + 1
            if left >= heap_size:
                break
            right = left + 1
            largest = root
            if arr[left] > arr[largest]:
                largest = left
            if right < heap_size and arr[right] > arr[largest]:
                largest = right
            if largest == root:
                break
            arr[root], arr[largest] = arr[largest], arr[root]
            root = largest

    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        sift_down(i, n)

    # Extract elements
    for end in range(n - 1, 0, -1):
        arr[0], arr[end] = arr[end], arr[0]
        sift_down(0, end)

    return arr


def _print_array(a: List[int]) -> None:
    print("[" + ", ".join(str(x) for x in a) + "]")


if __name__ == "__main__":
    try:
        tests = [
            [3, 1, 4, 1, 5, 9, 2, 6, 5],
            [],
            [42],
            [1, 2, 3, 4, 5],
            [0, -1, -3, 2, -1, 2, 0],
        ]
        for t in tests:
            _print_array(heap_sort(t))
    except ValueError as e:
        print(f"Error: {e}")