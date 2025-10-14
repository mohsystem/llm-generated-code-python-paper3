
def find_missing_number(arr, n):
    expected_sum = n * (n + 1) // 2
    actual_sum = sum(arr)
    return expected_sum - actual_sum

if __name__ == "__main__":
    # Test case 1
    test1 = [1, 2, 4, 5, 6]
    print(f"Test 1 - Missing number: {find_missing_number(test1, 6)}")
    
    # Test case 2
    test2 = [1, 2, 3, 4, 5, 6, 7, 9, 10]
    print(f"Test 2 - Missing number: {find_missing_number(test2, 10)}")
    
    # Test case 3
    test3 = [2, 3, 4, 5]
    print(f"Test 3 - Missing number: {find_missing_number(test3, 5)}")
    
    # Test case 4
    test4 = [1]
    print(f"Test 4 - Missing number: {find_missing_number(test4, 2)}")
    
    # Test case 5
    test5 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16]
    print(f"Test 5 - Missing number: {find_missing_number(test5, 16)}")
