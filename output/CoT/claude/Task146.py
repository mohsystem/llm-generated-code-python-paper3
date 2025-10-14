
def find_missing_number(arr):
    """\n    Finds the missing number in an array containing unique integers from 1 to n\n    :param arr: List of integers with one missing number\n    :return: The missing number\n    """
    if arr is None or len(arr) == 0:
        return 1
    
    n = len(arr) + 1
    # Using mathematical formula: sum of 1 to n = n*(n+1)/2
    expected_sum = n * (n + 1) // 2
    actual_sum = sum(arr)
    
    return expected_sum - actual_sum


def main():
    # Test case 1: Missing number is 5
    test1 = [1, 2, 3, 4, 6]
    print(f"Test 1 - Array: {test1}")
    print(f"Missing number: {find_missing_number(test1)}")
    print()
    
    # Test case 2: Missing number is 1
    test2 = [2, 3, 4, 5, 6]
    print(f"Test 2 - Array: {test2}")
    print(f"Missing number: {find_missing_number(test2)}")
    print()
    
    # Test case 3: Missing number is 10
    test3 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    print(f"Test 3 - Array: {test3}")
    print(f"Missing number: {find_missing_number(test3)}")
    print()
    
    # Test case 4: Missing number is 3
    test4 = [1, 2, 4, 5, 6, 7]
    print(f"Test 4 - Array: {test4}")
    print(f"Missing number: {find_missing_number(test4)}")
    print()
    
    # Test case 5: Array with single element missing (n=2)
    test5 = [2]
    print(f"Test 5 - Array: {test5}")
    print(f"Missing number: {find_missing_number(test5)}")
    print()


if __name__ == "__main__":
    main()
