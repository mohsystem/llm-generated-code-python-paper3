def find_max_subarray_sum(arr):
    """
    Finds the contiguous subarray with the maximum sum using Kadane's algorithm.

    :param arr: The input list of integers.
    :return: The maximum sum of a contiguous subarray. Returns 0 if the list is empty.
    """
    # Handle empty list case.
    if not arr:
        return 0

    max_so_far = arr[0]
    current_max = arr[0]

    for i in range(1, len(arr)):
        # Decide whether to extend the existing subarray or start a new one.
        current_max = max(arr[i], current_max + arr[i])
        # Update the overall maximum sum found so far.
        max_so_far = max(max_so_far, current_max)
        
    return max_so_far

if __name__ == "__main__":
    # Test Case 1: Mixed positive and negative numbers
    test1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]
    print(f"Array: {test1}")
    print(f"Maximum subarray sum: {find_max_subarray_sum(test1)}") # Expected: 6
    print()

    # Test Case 2: All positive numbers
    test2 = [1, 2, 3, 4, 5]
    print(f"Array: {test2}")
    print(f"Maximum subarray sum: {find_max_subarray_sum(test2)}") # Expected: 15
    print()

    # Test Case 3: All negative numbers
    test3 = [-2, -3, -4, -1, -2, -1, -5, -3]
    print(f"Array: {test3}")
    print(f"Maximum subarray sum: {find_max_subarray_sum(test3)}") # Expected: -1
    print()
    
    # Test Case 4: Single element array
    test4 = [5]
    print(f"Array: {test4}")
    print(f"Maximum subarray sum: {find_max_subarray_sum(test4)}") # Expected: 5
    print()
    
    # Test Case 5: Empty array
    test5 = []
    print(f"Array: {test5}")
    print(f"Maximum subarray sum: {find_max_subarray_sum(test5)}") # Expected: 0
    print()