def two_sum(numbers, target):
    """
    Finds two indices of numbers in a list that add up to a target value.

    :param numbers: The input list of integers.
    :param target: The target sum.
    :return: A tuple containing the two indices, or None if no solution is found.
    """
    for i in range(len(numbers)):
        for j in range(i + 1, len(numbers)):
            if numbers[i] + numbers[j] == target:
                return (i, j)
    # As per problem description, a solution always exists.
    return None

if __name__ == '__main__':
    # Test Case 1
    print(f"Test Case 1: {two_sum([1, 2, 3], 4)}") # Expected: (0, 2)

    # Test Case 2
    print(f"Test Case 2: {two_sum([1234, 5678, 9012], 14690)}") # Expected: (1, 2)

    # Test Case 3
    print(f"Test Case 3: {two_sum([2, 2, 3], 4)}") # Expected: (0, 1)

    # Test Case 4
    print(f"Test Case 4: {two_sum([3, 2, 4], 6)}") # Expected: (1, 2)

    # Test Case 5
    print(f"Test Case 5: {two_sum([2, 7, 11, 15], 9)}") # Expected: (0, 1)