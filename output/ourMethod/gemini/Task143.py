from typing import List, Optional

def sort_array(arr: Optional[List[int]]) -> None:
    """
    Sorts a list of integers in ascending order.
    The sorting is done in-place.

    Args:
        arr: The list of integers to be sorted. Can be None or empty.
    """
    # Rule #3: Validate input. Check for None.
    # An empty list is valid and requires no action.
    if arr is None:
        return
    
    # list.sort() is a highly optimized and safe sorting algorithm (Timsort).
    # It handles list boundaries correctly, adhering to Rule #4.
    arr.sort()

def main() -> None:
    """
    Main function for testing the sort_array function.
    """
    test_cases = [
        [],                                 # Test Case 1: Empty list
        [5, -2, 9, 1, 5, 6],                # Test Case 2: Mixed positive and negative numbers
        [1],                                # Test Case 3: Single element list
        [9, 8, 7, 6, 5, 4, 3, 2, 1],        # Test Case 4: Reverse sorted list
        [1, 2, 3, 4, 5, 6, 7, 8, 9]         # Test Case 5: Already sorted list
    ]
    
    for i, test_list in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        original_list_str = str(test_list)
        print(f"Original list: {original_list_str}")
        sort_array(test_list)
        print(f"Sorted list:   {test_list}")
        print()

if __name__ == "__main__":
    main()