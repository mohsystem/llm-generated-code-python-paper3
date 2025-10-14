import sys

def find_missing_number(arr):
    """
    Finds the missing number in a list containing n-1 unique integers from 1 to n.
    Python's integers handle arbitrary size, naturally preventing overflow issues.

    :param arr: The input list of unique integers. The list is expected to contain
                unique numbers from 1 to n (inclusive) with one number missing.
    :return: The missing integer.
    :raises ValueError: if the input list is None.
    """
    # Input validation for robustness.
    if arr is None:
        raise ValueError("Input list cannot be None.")
        
    # The complete list should contain 'n' numbers.
    # The list has n-1 numbers, so n = len(arr) + 1.
    n = len(arr) + 1
    
    # The formula for the sum of the first n integers is n * (n + 1) / 2.
    # Use // for integer division.
    expected_sum = n * (n + 1) // 2
    
    # sum() is an efficient way to calculate the sum of list elements.
    actual_sum = sum(arr)
    
    # The difference is the missing number.
    return expected_sum - actual_sum

if __name__ == "__main__":
    # Test Case 1: A standard case with a missing number in the middle.
    arr1 = [1, 2, 4, 5]
    print(f"Test Case 1: Array = {arr1}, Missing number: {find_missing_number(arr1)}")

    # Test Case 2: An unordered array.
    arr2 = [5, 2, 1, 4]
    print(f"Test Case 2: Array = {arr2}, Missing number: {find_missing_number(arr2)}")

    # Test Case 3: A small array where the last number is missing.
    arr3 = [1]
    print(f"Test Case 3: Array = {arr3}, Missing number: {find_missing_number(arr3)}")

    # Test Case 4: An empty list. Here n=1, so the missing number is 1.
    arr4 = []
    print(f"Test Case 4: Array = {arr4}, Missing number: {find_missing_number(arr4)}")

    # Test Case 5: A larger array.
    arr5 = [1, 2, 3, 4, 5, 6, 7, 9, 10]
    print(f"Test Case 5: Array = {arr5}, Missing number: {find_missing_number(arr5)}")