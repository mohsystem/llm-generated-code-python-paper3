import sys

def sort_array(arr):
    """
    Sorts a list of integers in ascending order.
    This function sorts the list in-place.

    Args:
        arr: The list of integers to be sorted.
    """
    # Secure: Check for None input to prevent AttributeError.
    if arr is None:
        print("Input list cannot be None.", file=sys.stderr)
        return
    
    # Secure: Python's Timsort is highly optimized and stable,
    # protecting against worst-case scenarios found in other
    # sorting algorithms.
    arr.sort()

if __name__ == "__main__":
    # Test Case 1: Regular unsorted list
    print("--- Test Case 1: Regular unsorted list ---")
    test1 = [5, 2, 8, 1, 9, 4]
    print(f"Before: {test1}")
    sort_array(test1)
    print(f"After:  {test1}")
    print()

    # Test Case 2: list with negative numbers and duplicates
    print("--- Test Case 2: list with negative numbers and duplicates ---")
    test2 = [-5, 2, -8, 2, 9, 4, -5]
    print(f"Before: {test2}")
    sort_array(test2)
    print(f"After:  {test2}")
    print()
    
    # Test Case 3: Already sorted list
    print("--- Test Case 3: Already sorted list ---")
    test3 = [1, 2, 3, 4, 5, 6]
    print(f"Before: {test3}")
    sort_array(test3)
    print(f"After:  {test3}")
    print()

    # Test Case 4: Reverse sorted list
    print("--- Test Case 4: Reverse sorted list ---")
    test4 = [10, 8, 6, 4, 2, 0]
    print(f"Before: {test4}")
    sort_array(test4)
    print(f"After:  {test4}")
    print()

    # Test Case 5: Empty list and None list
    print("--- Test Case 5: Edge cases (empty and None) ---")
    test5_empty = []
    print(f"Before (empty): {test5_empty}")
    sort_array(test5_empty)
    print(f"After (empty):  {test5_empty}")
    
    test5_none = None
    print(f"Before (None): {test5_none}")
    sort_array(test5_none) # The function will print an error message
    print()