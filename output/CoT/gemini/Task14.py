def find_even_index(arr):
    """
    Finds an index N in an array of integers where the sum of the integers
    to the left of N is equal to the sum of the integers to the right of N.

    :param arr: The input list of integers.
    :return: The lowest index N that satisfies the condition, or -1 if no such index exists.
    """
    total_sum = sum(arr)
    left_sum = 0
    for i, num in enumerate(arr):
        # The right sum is the total sum minus the left sum and the current element
        right_sum = total_sum - left_sum - num
        
        if left_sum == right_sum:
            return i  # Found the equilibrium index
        
        # Update the left sum for the next iteration
        left_sum += num
        
    return -1  # No such index found

# Main block with test cases
if __name__ == '__main__':
    # Test Case 1
    test1 = [1, 2, 3, 4, 3, 2, 1]
    print(f"Array: {test1}")
    print(f"Expected: 3, Actual: {find_even_index(test1)}\n")

    # Test Case 2
    test2 = [1, 100, 50, -51, 1, 1]
    print(f"Array: {test2}")
    print(f"Expected: 1, Actual: {find_even_index(test2)}\n")

    # Test Case 3
    test3 = [20, 10, -80, 10, 10, 15, 35]
    print(f"Array: {test3}")
    print(f"Expected: 0, Actual: {find_even_index(test3)}\n")

    # Test Case 4
    test4 = [10, -80, 10, 10, 15, 35, 20]
    print(f"Array: {test4}")
    print(f"Expected: 6, Actual: {find_even_index(test4)}\n")

    # Test Case 5 (No solution)
    test5 = [1, 2, 3, 4, 5, 6]
    print(f"Array: {test5}")
    print(f"Expected: -1, Actual: {find_even_index(test5)}\n")