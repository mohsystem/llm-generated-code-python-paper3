def find_missing_number(arr):
    """
    Finds the missing number in an array of unique integers from 1 to n.
    """
    # The array is supposed to have numbers from 1 to n, but has n-1 elements.
    # So, n is the length of the array + 1.
    n = len(arr) + 1
    
    # Calculate the expected sum of the first n natural numbers.
    expected_sum = n * (n + 1) // 2
    
    # Calculate the actual sum of elements in the array.
    actual_sum = sum(arr)
    
    # The difference is the missing number.
    return expected_sum - actual_sum

if __name__ == "__main__":
    # Test Case 1
    arr1 = [1, 2, 4, 5]
    print(f"Test Case 1: Missing number in [1, 2, 4, 5] is {find_missing_number(arr1)}")

    # Test Case 2
    arr2 = [2, 3, 1, 5]
    print(f"Test Case 2: Missing number in [2, 3, 1, 5] is {find_missing_number(arr2)}")

    # Test Case 3
    arr3 = [1]
    print(f"Test Case 3: Missing number in [1] is {find_missing_number(arr3)}")

    # Test Case 4
    arr4 = [1, 2, 3, 4, 5, 6, 8, 9]
    print(f"Test Case 4: Missing number in [1, 2, 3, 4, 5, 6, 8, 9] is {find_missing_number(arr4)}")
    
    # Test Case 5
    arr5 = [2]
    print(f"Test Case 5: Missing number in [2] is {find_missing_number(arr5)}")