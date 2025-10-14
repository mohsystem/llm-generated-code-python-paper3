from typing import List

def find_kth_largest(nums: List[int], k: int) -> int:
    """
    Finds the kth largest element in a list of integers.
    This implementation sorts a copy of the list and picks the element at the correct index.

    Args:
        nums: The input list of integers.
        k: The rank of the element to find (1-based index).

    Returns:
        The kth largest element.

    Raises:
        ValueError: If the input is invalid (e.g., empty list, k is out of bounds).
    """
    if not nums or k <= 0 or k > len(nums):
        raise ValueError("Invalid input: list must not be empty, and k must be within the bounds [1, list.length].")

    # sorted() returns a new sorted list, so the original list is not modified.
    # The kth largest element in an ascending sorted list is at index len(nums) - k.
    sorted_nums = sorted(nums)
    return sorted_nums[len(nums) - k]

def main():
    """Main function with test cases."""
    test_cases = [
        ({"nums": [3, 2, 1, 5, 6, 4], "k": 2}, 5),
        ({"nums": [3, 2, 3, 1, 2, 4, 5, 5, 6], "k": 4}, 4),
        ({"nums": [1], "k": 1}, 1),
        ({"nums": [99, 99], "k": 1}, 99),
        ({"nums": [-1, -1, -2, -5], "k": 3}, -2),
    ]

    for i, (params, expected) in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Input list: {params['nums']}")
        print(f"k: {params['k']}")
        try:
            result = find_kth_largest(params["nums"], params["k"])
            print(f"Result: {result}")
            print(f"Expected: {expected}")
            if result == expected:
                print("Status: PASSED")
            else:
                print("Status: FAILED")
        except ValueError as e:
            print(f"Caught exception: {e}")
            print("Status: FAILED (exception not expected)")
        print("--------------------")

    # Additional test case for invalid input
    print("Test Case 6: Invalid k (k=4 for list of size 3)")
    try:
        find_kth_largest([1, 2, 3], 4)
        print("Status: FAILED (exception was expected)")
    except ValueError as e:
        print(f"Caught expected exception: {e}")
        print("Status: PASSED")
    print("--------------------")

if __name__ == "__main__":
    main()