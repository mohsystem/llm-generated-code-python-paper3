def max_sub_array_sum(arr):
    """
    Finds the contiguous subarray with the maximum sum using Kadane's algorithm.
    :param arr: The input list of integers.
    :return: The maximum sum of a contiguous subarray.
    """
    if not arr:
        return 0  # The sum of an empty subarray is 0.

    max_so_far = arr[0]
    current_max = arr[0]

    for num in arr[1:]:
        current_max = max(num, current_max + num)
        max_so_far = max(max_so_far, current_max)

    return max_so_far

if __name__ == "__main__":
    # Test Case 1
    arr1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]
    print(f"Max sum for {arr1} is: {max_sub_array_sum(arr1)}")

    # Test Case 2
    arr2 = [1]
    print(f"Max sum for {arr2} is: {max_sub_array_sum(arr2)}")

    # Test Case 3
    arr3 = [5, 4, -1, 7, 8]
    print(f"Max sum for {arr3} is: {max_sub_array_sum(arr3)}")

    # Test Case 4
    arr4 = [-5, -1, -3]
    print(f"Max sum for {arr4} is: {max_sub_array_sum(arr4)}")

    # Test Case 5
    arr5 = [-2, -3, 4, -1, -2, 1, 5, -3]
    print(f"Max sum for {arr5} is: {max_sub_array_sum(arr5)}")