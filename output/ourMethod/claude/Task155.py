
from typing import List, Optional

MAX_ARRAY_SIZE = 1000000

def heap_sort(arr: List[int]) -> List[int]:
    """Sorts an array using heap sort algorithm."""
    if arr is None:
        raise ValueError("Input array cannot be None")
    
    if len(arr) > MAX_ARRAY_SIZE:
        raise ValueError("Array size exceeds maximum allowed size")
    
    result = arr.copy()
    n = len(result)
    
    for i in range(n // 2 - 1, -1, -1):
        heapify(result, n, i)
    
    for i in range(n - 1, 0, -1):
        result[0], result[i] = result[i], result[0]
        heapify(result, i, 0)
    
    return result

def heapify(arr: List[int], n: int, i: int) -> None:
    """Heapify subtree rooted at index i."""
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2
    
    if left < n and arr[left] > arr[largest]:
        largest = left
    
    if right < n and arr[right] > arr[largest]:
        largest = right
    
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest)

def main() -> None:
    """Test the heap sort implementation with multiple test cases."""
    test_cases = [
        [64, 34, 25, 12, 22, 11, 90],
        [5, 2, 8, 1, 9],
        [-5, -2, -8, -1, -9],
        [1],
        [100, 50, 75, 25, 30, 60, 80]
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        try:
            original = test_case.copy()
            sorted_arr = heap_sort(test_case)
            print(f"Test case {i}:")
            print(f"Original: {original}")
            print(f"Sorted:   {sorted_arr}")
            print()
        except ValueError as e:
            print(f"Error in test case {i}: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
