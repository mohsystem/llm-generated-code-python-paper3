from typing import List, Optional

def sort_array(arr: List[int]) -> Optional[List[int]]:
    """
    Sorts a list of integers in ascending order.
    
    :param arr: The list of integers to sort.
    :return: A new list containing the sorted integers, or None if input is None.
    """
    if arr is None:
        return None
    return sorted(arr)

def main():
    """Main function to run test cases."""
    test_cases = [
        # Test Case 1: Standard unsorted array
        [5, 2, 8, 1, 9],
        # Test Case 2: Reverse-sorted array
        [9, 8, 7, 6, 5, 4, 3, 2, 1],
        # Test Case 3: Already sorted array
        [1, 2, 3, 4, 5],
        # Test Case 4: Array with duplicate elements
        [4, 2, 7, 2, 5, 4],
        # Test Case 5: Array with negative numbers and zero
        [-5, 0, 10, -2, 3]
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}")
        print(f"Original: {test_case}")
        sorted_arr = sort_array(test_case)
        print(f"Sorted:   {sorted_arr}")
        print()

if __name__ == "__main__":
    main()