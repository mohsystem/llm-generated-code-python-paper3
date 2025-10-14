
from typing import List

def max_subarray_sum(arr: List[int]) -> int:
    """\n    Finds the contiguous subarray with maximum sum using Kadane's algorithm.\n    \n    Args:\n        arr: Input list of integers\n        \n    Returns:\n        Maximum sum of contiguous subarray\n        \n    Raises:\n        ValueError: If array is None or empty\n        TypeError: If input is not a list or contains non-integers\n    """
    # Input validation
    if arr is None:
        raise ValueError("Array cannot be None")
    if not isinstance(arr, list):
        raise TypeError("Input must be a list")
    if len(arr) == 0:
        raise ValueError("Array cannot be empty")
    
    # Validate all elements are integers
    for i, elem in enumerate(arr):
        if not isinstance(elem, int):
            raise TypeError(f"Element at index {i} is not an integer")
    
    max_so_far = arr[0]
    max_ending_here = arr[0]
    
    for i in range(1, len(arr)):
        max_ending_here = max(arr[i], max_ending_here + arr[i])
        max_so_far = max(max_so_far, max_ending_here)
    
    return max_so_far


def main() -> None:
    # Test case 1: Mixed positive and negative numbers
    test1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]
    print(f"Test 1: {test1}")
    print(f"Maximum subarray sum: {max_subarray_sum(test1)}")
    print()
    
    # Test case 2: All positive numbers
    test2 = [1, 2, 3, 4, 5]
    print(f"Test 2: {test2}")
    print(f"Maximum subarray sum: {max_subarray_sum(test2)}")
    print()
    
    # Test case 3: All negative numbers
    test3 = [-5, -2, -8, -1, -4]
    print(f"Test 3: {test3}")
    print(f"Maximum subarray sum: {max_subarray_sum(test3)}")
    print()
    
    # Test case 4: Single element
    test4 = [42]
    print(f"Test 4: {test4}")
    print(f"Maximum subarray sum: {max_subarray_sum(test4)}")
    print()
    
    # Test case 5: Large numbers
    test5 = [1000000000, 1000000000, -500000000, 1000000000]
    print(f"Test 5: {test5}")
    print(f"Maximum subarray sum: {max_subarray_sum(test5)}")


if __name__ == "__main__":
    main()
