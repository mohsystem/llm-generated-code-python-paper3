from typing import List

def find_max_subarray_sum(nums: List[int]) -> int:
    """
    Finds the contiguous subarray with the maximum sum using Kadane's algorithm.

    Args:
        nums: The input list of integers.

    Returns:
        The maximum sum of a contiguous subarray.

    Raises:
        ValueError: If the input list is null or empty.
    """
    if not nums:
        raise ValueError("Input array cannot be empty.")

    max_so_far = nums[0]
    current_max = nums[0]

    for i in range(1, len(nums)):
        current_max = max(nums[i], current_max + nums[i])
        max_so_far = max(max_so_far, current_max)
        
    return max_so_far

def main():
    """Main function with test cases."""
    test_cases = {
        "Test Case 1": ([-2, 1, -3, 4, -1, 2, 1, -5, 4]),
        "Test Case 2": ([5, 4, -1, 7, 8]),
        "Test Case 3": ([-2, -3, -1, -5]),
        "Test Case 4": ([5]),
        "Test Case 5": ([8, -19, 5, -4, 20])
    }

    for name, test_input in test_cases.items():
        print(f"{name}: {test_input}")
        try:
            result = find_max_subarray_sum(test_input)
            print(f"Max sum: {result}\n")
        except ValueError as e:
            print(f"Error: {e}\n")


if __name__ == "__main__":
    main()