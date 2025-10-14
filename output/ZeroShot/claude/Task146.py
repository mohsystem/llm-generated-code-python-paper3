
def find_missing_number(arr, n):
    # Calculate expected sum of 1 to n
    expected_sum = n * (n + 1) // 2
    
    # Calculate actual sum of array elements
    actual_sum = sum(arr)
    
    # Missing number is the difference
    return expected_sum - actual_sum


if __name__ == "__main__":
    # Test case 1: Missing number is 5
    test1 = [1, 2, 3, 4, 6, 7, 8, 9, 10]
    print(f"Test 1 - Missing number: {find_missing_number(test1, 10)}")
    
    # Test case 2: Missing number is 1
    test2 = [2, 3, 4, 5]
    print(f"Test 2 - Missing number: {find_missing_number(test2, 5)}")
    
    # Test case 3: Missing number is 10
    test3 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    print(f"Test 3 - Missing number: {find_missing_number(test3, 10)}")
    
    # Test case 4: Missing number is 3
    test4 = [1, 2, 4, 5, 6]
    print(f"Test 4 - Missing number: {find_missing_number(test4, 6)}")
    
    # Test case 5: Missing number is 7
    test5 = [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12]
    print(f"Test 5 - Missing number: {find_missing_number(test5, 12)}")
