def find_missing_number(nums):
    """
    Finds the missing number in a list containing n-1 unique integers
    from the range [1, n].

    Args:
        nums: The input list of unique integers.

    Returns:
        The missing integer.
    """
    if nums is None:
        return 0 # Or raise an error based on requirements

    # 'n' is the expected size of the complete sequence
    n = len(nums) + 1

    # Formula for the sum of the first n natural numbers
    expected_sum = n * (n + 1) // 2
    
    # Calculate the actual sum of the elements in the list
    actual_sum = sum(nums)
    
    # The difference is the missing number
    return expected_sum - actual_sum

if __name__ == '__main__':
    # Test Case 1
    arr1 = [1, 2, 4, 5]
    print(f"Test Case 1: Input: {arr1}, Missing Number: {find_missing_number(arr1)}")

    # Test Case 2
    arr2 = [2, 3, 1, 5]
    print(f"Test Case 2: Input: {arr2}, Missing Number: {find_missing_number(arr2)}")

    # Test Case 3
    arr3 = [1]
    print(f"Test Case 3: Input: {arr3}, Missing Number: {find_missing_number(arr3)}")

    # Test Case 4
    arr4 = [2]
    print(f"Test Case 4: Input: {arr4}, Missing Number: {find_missing_number(arr4)}")

    # Test Case 5 (Edge case: empty list)
    arr5 = []
    print(f"Test Case 5: Input: {arr5}, Missing Number: {find_missing_number(arr5)}")