def longestRun(arr):
    """
    Calculates the length of the longest consecutive-run in a list of numbers.
    A consecutive-run is a list of adjacent, consecutive integers, either increasing or decreasing.

    :param arr: The input list of integers.
    :return: The length of the longest consecutive run.
    """
    if not arr:
        return 0
    if len(arr) == 1:
        return 1

    max_run = 1
    current_run = 1
    # direction: 0 = undecided, 1 = increasing, -1 = decreasing
    direction = 0

    for i in range(1, len(arr)):
        if arr[i] == arr[i - 1] + 1:  # Increasing
            if direction == 1:
                current_run += 1
            else:
                current_run = 2
                direction = 1
        elif arr[i] == arr[i - 1] - 1:  # Decreasing
            if direction == -1:
                current_run += 1
            else:
                current_run = 2
                direction = -1
        else:  # Run broken
            current_run = 1
            direction = 0
        
        if current_run > max_run:
            max_run = current_run
            
    return max_run

if __name__ == '__main__':
    # Test Case 1
    arr1 = [1, 2, 3, 5, 6, 7, 8, 9]
    print("Test 1: longestRun([1, 2, 3, 5, 6, 7, 8, 9])")
    print(f"Expected: 5, Got: {longestRun(arr1)}")

    # Test Case 2
    arr2 = [1, 2, 3, 10, 11, 15]
    print("\nTest 2: longestRun([1, 2, 3, 10, 11, 15])")
    print(f"Expected: 3, Got: {longestRun(arr2)}")

    # Test Case 3
    arr3 = [5, 4, 2, 1]
    print("\nTest 3: longestRun([5, 4, 2, 1])")
    print(f"Expected: 2, Got: {longestRun(arr3)}")

    # Test Case 4
    arr4 = [3, 5, 7, 10, 15]
    print("\nTest 4: longestRun([3, 5, 7, 10, 15])")
    print(f"Expected: 1, Got: {longestRun(arr4)}")

    # Test Case 5
    arr5 = [1, 0, -1, -2, 5, 6, 5, 4, 3, 2, 1]
    print("\nTest 5: longestRun([1, 0, -1, -2, 5, 6, 5, 4, 3, 2, 1])")
    print(f"Expected: 6, Got: {longestRun(arr5)}")