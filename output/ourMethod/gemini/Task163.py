from typing import List

def longestRun(arr: List[int]) -> int:
    """
    Calculates the length of the longest consecutive-run in a list of numbers.
    A consecutive-run is a list of adjacent, consecutive integers,
    which can be either increasing or decreasing.

    :param arr: The input list of integers.
    :return: The length of the longest consecutive-run.
    """
    if not arr:
        return 0
    if len(arr) == 1:
        return 1

    max_length = 1
    current_increasing_length = 1
    current_decreasing_length = 1

    for i in range(1, len(arr)):
        if arr[i] == arr[i - 1] + 1:
            current_increasing_length += 1
            current_decreasing_length = 1
        elif arr[i] == arr[i - 1] - 1:
            current_decreasing_length += 1
            current_increasing_length = 1
        else:
            current_increasing_length = 1
            current_decreasing_length = 1
        
        max_length = max(max_length, current_increasing_length, current_decreasing_length)

    return max_length

if __name__ == '__main__':
    # Test cases
    test1 = [1, 2, 3, 5, 6, 7, 8, 9]
    print(f"longestRun([1, 2, 3, 5, 6, 7, 8, 9]) -> {longestRun(test1)}")

    test2 = [1, 2, 3, 10, 11, 15]
    print(f"longestRun([1, 2, 3, 10, 11, 15]) -> {longestRun(test2)}")

    test3 = [5, 4, 2, 1]
    print(f"longestRun([5, 4, 2, 1]) -> {longestRun(test3)}")

    test4 = [3, 5, 7, 10, 15]
    print(f"longestRun([3, 5, 7, 10, 15]) -> {longestRun(test4)}")
    
    test5 = [1, 2, 3, 2, 1, 0, 1, 2]
    print(f"longestRun([1, 2, 3, 2, 1, 0, 1, 2]) -> {longestRun(test5)}")