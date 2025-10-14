
def max_subarray_sum(arr):
    """\n    Finds the contiguous subarray with maximum sum using Kadane's algorithm\n    :param arr: input list of integers\n    :return: maximum sum of contiguous subarray\n    """
    # Input validation
    if not arr or len(arr) == 0:
        raise ValueError("Array cannot be None or empty")
    
    if not isinstance(arr, list):
        raise TypeError("Input must be a list")
    
    max_sum = arr[0]
    current_sum = arr[0]
    
    # Kadane's algorithm
    for i in range(1, len(arr)):
        current_sum = max(arr[i], current_sum + arr[i])
        max_sum = max(max_sum, current_sum)
    
    return max_sum


def main():
    # Test case 1: Mixed positive and negative numbers
    test1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]
    print(f"Test 1: {test1}")
    print(f"Maximum subarray sum: {max_subarray_sum(test1)}")
    print()
    
    # Test case 2: All negative numbers
    test2 = [-5, -2, -8, -1, -4]
    print(f"Test 2: {test2}")
    print(f"Maximum subarray sum: {max_subarray_sum(test2)}")
    print()
    
    # Test case 3: All positive numbers
    test3 = [1, 2, 3, 4, 5]
    print(f"Test 3: {test3}")
    print(f"Maximum subarray sum: {max_subarray_sum(test3)}")
    print()
    
    # Test case 4: Single element
    test4 = [10]
    print(f"Test 4: {test4}")
    print(f"Maximum subarray sum: {max_subarray_sum(test4)}")
    print()
    
    # Test case 5: Large numbers
    test5 = [-1, -2, 5, -3, 4, 6, -2]
    print(f"Test 5: {test5}")
    print(f"Maximum subarray sum: {max_subarray_sum(test5)}")


if __name__ == "__main__":
    main()
