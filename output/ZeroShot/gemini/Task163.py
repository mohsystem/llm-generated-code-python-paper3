def longest_run(arr):
    """
    Finds the length of the longest consecutive run in a list of numbers.
    A consecutive run can be either increasing or decreasing.
    
    :param arr: A list of integers.
    :return: The length of the longest consecutive run.
    """
    if not arr:
        return 0
    
    n = len(arr)
    if n == 1:
        return 1

    max_length = 1
    current_inc_length = 1
    current_dec_length = 1

    for i in range(1, n):
        # Check for an increasing run
        if arr[i] == arr[i - 1] + 1:
            current_inc_length += 1
        else:
            current_inc_length = 1

        # Check for a decreasing run
        if arr[i] == arr[i - 1] - 1:
            current_dec_length += 1
        else:
            current_dec_length = 1
            
        # Update the maximum length found so far
        max_length = max(max_length, current_inc_length, current_dec_length)
        
    return max_length

if __name__ == '__main__':
    # Test Case 1: Long increasing run
    test1 = [1, 2, 3, 5, 6, 7, 8, 9]
    print(f"Test 1: {test1} -> Expected: 5, Got: {longest_run(test1)}")

    # Test Case 2: Long decreasing run
    test2 = [9, 8, 7, 6, 3, 2, 1]
    print(f"Test 2: {test2} -> Expected: 4, Got: {longest_run(test2)}")

    # Test Case 3: Mixed runs
    test3 = [1, 2, 1, 0, -1, 4, 5]
    print(f"Test 3: {test3} -> Expected: 4, Got: {longest_run(test3)}")

    # Test Case 4: No consecutive runs
    test4 = [3, 5, 7, 10, 15]
    print(f"Test 4: {test4} -> Expected: 1, Got: {longest_run(test4)}")

    # Test Case 5: Empty list
    test5 = []
    print(f"Test 5: {test5} -> Expected: 0, Got: {longest_run(test5)}")