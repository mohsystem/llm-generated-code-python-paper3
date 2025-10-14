
import heapq
from typing import List

def find_kth_largest(arr: List[int], k: int) -> int:
    """\n    Finds the kth largest element in an array using a min-heap.\n    \n    Args:\n        arr: The input list of integers\n        k: The position of the largest element to find (1-indexed)\n    \n    Returns:\n        The kth largest element\n    \n    Raises:\n        ValueError: if inputs are invalid\n    """
    # Input validation
    if arr is None:
        raise ValueError("Array cannot be None")
    if not isinstance(arr, list):
        raise ValueError("Input must be a list")
    if len(arr) == 0:
        raise ValueError("Array cannot be empty")
    if not isinstance(k, int):
        raise ValueError("k must be an integer")
    if k < 1 or k > len(arr):
        raise ValueError(f"k must be between 1 and {len(arr)}")
    
    # Validate all elements are integers
    for i, elem in enumerate(arr):
        if not isinstance(elem, int):
            raise ValueError(f"All array elements must be integers, found {type(elem)} at index {i}")
    
    # Use a min-heap of size k to track the k largest elements
    min_heap: List[int] = []
    
    for num in arr:
        heapq.heappush(min_heap, num)
        if len(min_heap) > k:
            heapq.heappop(min_heap)
    
    # The root of the min-heap is the kth largest element
    if len(min_heap) == 0:
        raise ValueError("Unexpected empty heap")
    
    return min_heap[0]

def main() -> None:
    """Test the find_kth_largest function with multiple test cases."""
    try:
        # Test case 1: Normal case
        arr1 = [3, 2, 1, 5, 6, 4]
        k1 = 2
        print(f"Test 1: arr={arr1}, k={k1} => {find_kth_largest(arr1, k1)}")
        
        # Test case 2: k=1 (largest element)
        arr2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
        k2 = 1
        print(f"Test 2: arr={arr2}, k={k2} => {find_kth_largest(arr2, k2)}")
        
        # Test case 3: k equals array length (smallest element)
        arr3 = [7, 10, 4, 3, 20, 15]
        k3 = 6
        print(f"Test 3: arr={arr3}, k={k3} => {find_kth_largest(arr3, k3)}")
        
        # Test case 4: Array with duplicates
        arr4 = [1, 1, 1, 1, 1]
        k4 = 3
        print(f"Test 4: arr={arr4}, k={k4} => {find_kth_largest(arr4, k4)}")
        
        # Test case 5: Single element array
        arr5 = [42]
        k5 = 1
        print(f"Test 5: arr={arr5}, k={k5} => {find_kth_largest(arr5, k5)}")
        
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
