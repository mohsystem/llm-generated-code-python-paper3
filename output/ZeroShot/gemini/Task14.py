def find_even_index(arr):
    """
    Finds an index in an array of integers where the sum of integers to the left
    of the index is equal to the sum of integers to the right.
    
    Args:
        arr: The input list of integers.
    
    Returns:
        The lowest index N where the condition is met, or -1 if no such index exists.
    """
    # Python's integers handle arbitrary size, so overflow is not an issue.
    total_sum = sum(arr)
    left_sum = 0
    for i, num in enumerate(arr):
        # The sum of the right side is the total sum minus the left sum and the current element.
        right_sum = total_sum - left_sum - num
        if left_sum == right_sum:
            return i
        left_sum += num
    
    return -1 # Return -1 if no such index is found.

if __name__ == '__main__':
    # Test Case 1: Example from prompt
    test1 = [1, 2, 3, 4, 3, 2, 1]
    print(f"Array: {test1} -> Index: {find_even_index(test1)}")

    # Test Case 2: Example from prompt
    test2 = [1, 100, 50, -51, 1, 1]
    print(f"Array: {test2} -> Index: {find_even_index(test2)}")

    # Test Case 3: Example from prompt (index 0)
    test3 = [20, 10, -80, 10, 10, 15, 35]
    print(f"Array: {test3} -> Index: {find_even_index(test3)}")
    
    # Test Case 4: Index is the last element
    test4 = [10, -80, 10, 10, 15, 35, 20]
    print(f"Array: {test4} -> Index: {find_even_index(test4)}")

    # Test Case 5: No solution
    test5 = [1, 2, 3, 4, 5, 6]
    print(f"Array: {test5} -> Index: {find_even_index(test5)}")