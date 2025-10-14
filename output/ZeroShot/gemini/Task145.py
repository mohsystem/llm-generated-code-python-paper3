def max_sub_array_sum(arr):
    """
    Finds the contiguous subarray with the maximum sum using Kadane's algorithm.
    
    :param arr: A list of integers.
    :return: The sum of the maximum contiguous subarray. Returns 0 if the list is empty.
    """
    # Secure: Handle empty list to prevent errors.
    if not arr:
        return 0

    # Python integers have arbitrary precision, so overflow is not a concern for the sum.
    max_so_far = arr[0]
    current_max = arr[0]

    # Iterate from the second element
    for num in arr[1:]:
        # The maximum subarray ending at the current position is either the number itself
        # or the number plus the maximum subarray ending at the previous position.
        current_max = max(num, current_max + num)
        
        # Update the overall maximum sum found so far.
        max_so_far = max(max_so_far, current_max)
        
    return max_so_far

if __name__ == "__main__":
    # 5 test cases
    test_cases = [
        [-2, 1, -3, 4, -1, 2, 1, -5, 4],  # Expected: 6, Subarray: [4, -1, 2, 1]
        [1, 2, 3, 4, 5],                 # Expected: 15, Subarray: [1, 2, 3, 4, 5]
        [-2, -3, -4, -1, -5],             # Expected: -1, Subarray: [-1]
        [5],                              # Expected: 5, Subarray: [5]
        [8, -19, 5, -4, 20]              # Expected: 21, Subarray: [5, -4, 20]
    ]
    
    for i, arr in enumerate(test_cases, 1):
        result = max_sub_array_sum(arr)
        print(f"Test Case {i}: Array = {arr}, Max Subarray Sum = {result}")