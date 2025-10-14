
from typing import List

MAX_ARRAY_SIZE = 100000

def merge_sorted_arrays(arr1: List[int], arr2: List[int]) -> List[int]:
    if arr1 is None or arr2 is None:
        raise ValueError("Input arrays must not be None")
    
    if not isinstance(arr1, list) or not isinstance(arr2, list):
        raise TypeError("Inputs must be lists")
    
    if len(arr1) > MAX_ARRAY_SIZE or len(arr2) > MAX_ARRAY_SIZE:
        raise ValueError("Array size exceeds maximum allowed size")
    
    total_size = len(arr1) + len(arr2)
    if total_size > MAX_ARRAY_SIZE:
        raise ValueError("Combined array size exceeds maximum allowed size")
    
    for val in arr1:
        if not isinstance(val, int):
            raise TypeError("All elements in arr1 must be integers")
    
    for val in arr2:
        if not isinstance(val, int):
            raise TypeError("All elements in arr2 must be integers")
    
    result = []
    i = 0
    j = 0
    
    while i < len(arr1) and j < len(arr2):
        if arr1[i] <= arr2[j]:
            result.append(arr1[i])
            i += 1
        else:
            result.append(arr2[j])
            j += 1
    
    while i < len(arr1):
        result.append(arr1[i])
        i += 1
    
    while j < len(arr2):
        result.append(arr2[j])
        j += 1
    
    return result

if __name__ == "__main__":
    test_cases = [
        ([1, 3, 5, 7], [2, 4, 6, 8]),
        ([1, 2, 3], [4, 5, 6]),
        ([], [1, 2, 3]),
        ([1], [2]),
        ([-5, -2, 0, 3], [-3, -1, 2, 4])
    ]
    
    for idx, (arr1, arr2) in enumerate(test_cases, 1):
        print(f"Test Case {idx}:")
        print(f"Input: {arr1}, {arr2}")
        print(f"Output: {merge_sorted_arrays(arr1, arr2)}")
        print()
