def longestRun(arr):
    """
    Calculates the length of the longest consecutive run in an array.
    A consecutive run can be either increasing or decreasing.

    :param arr: The input list of integers.
    :return: The length of the longest consecutive run.
    """
    if not arr:
        return 0
    n = len(arr)
    if n == 1:
        return 1

    max_length = 1
    current_increasing = 1
    current_decreasing = 1

    for i in range(1, n):
        if arr[i] == arr[i - 1] + 1:
            # Increasing run continues
            current_increasing += 1
            # Reset decreasing run
            current_decreasing = 1
        elif arr[i] == arr[i - 1] - 1:
            # Decreasing run continues
            current_decreasing += 1
            # Reset increasing run
            current_increasing = 1
        else:
            # Run is broken
            current_increasing = 1
            current_decreasing = 1
        
        max_length = max(max_length, current_increasing, current_decreasing)
    
    return max_length

if __name__ == '__main__':
    # Test Case 1
    arr1 = [1, 2, 3, 5, 6, 7, 8, 9]
    print(f"Test Case 1: {arr1} -> {longestRun(arr1)}")  # Expected: 5

    # Test Case 2
    arr2 = [1, 2, 3, 10, 11, 15]
    print(f"Test Case 2: {arr2} -> {longestRun(arr2)}")  # Expected: 3

    # Test Case 3
    arr3 = [5, 4, 2, 1]
    print(f"Test Case 3: {arr3} -> {longestRun(arr3)}")  # Expected: 2

    # Test Case 4
    arr4 = [3, 5, 7, 10, 15]
    print(f"Test Case 4: {arr4} -> {longestRun(arr4)}")  # Expected: 1

    # Test Case 5
    arr5 = [1, 0, -1, -2, -1, 0, 1, 2, 3]
    print(f"Test Case 5: {arr5} -> {longestRun(arr5)}")  # Expected: 6