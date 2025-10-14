
from typing import List

MAX_ARRAY_SIZE = 10000

def sort_array(arr: List[int]) -> List[int]:
    """\n    Sorts an array of integers in ascending order.\n    \n    Args:\n        arr: List of integers to sort\n        \n    Returns:\n        A new sorted list of integers\n        \n    Raises:\n        TypeError: If input is not a list or contains non-integers\n        ValueError: If array size exceeds maximum allowed size\n    """
    if not isinstance(arr, list):
        raise TypeError("Input must be a list")
    
    if len(arr) > MAX_ARRAY_SIZE:
        raise ValueError("Array size exceeds maximum allowed size")
    
    for item in arr:
        if not isinstance(item, int):
            raise TypeError("All elements must be integers")
    
    result = arr.copy()
    result.sort()
    return result

def main():
    # Test case 1: Normal array
    test1 = [5, 2, 8, 1, 9]
    print(f"Test 1: {sort_array(test1)}")
    
    # Test case 2: Already sorted array
    test2 = [1, 2, 3, 4, 5]
    print(f"Test 2: {sort_array(test2)}")
    
    # Test case 3: Reverse sorted array
    test3 = [9, 7, 5, 3, 1]
    print(f"Test 3: {sort_array(test3)}")
    
    # Test case 4: Array with duplicates
    test4 = [3, 1, 4, 1, 5, 9, 2, 6, 5]
    print(f"Test 4: {sort_array(test4)}")
    
    # Test case 5: Single element array
    test5 = [42]
    print(f"Test 5: {sort_array(test5)}")

if __name__ == "__main__":
    main()
