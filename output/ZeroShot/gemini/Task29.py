def two_sum(numbers, target):
    """
    Finds two different items in the array that sum up to the target value.
    This implementation uses a dictionary (hash map) for O(n) time complexity.
    
    :param numbers: A list of numbers.
    :param target: The target number.
    :return: A list containing the indices of the two numbers.
    """
    num_map = {}
    for i, num in enumerate(numbers):
        complement = target - num
        if complement in num_map:
            return [num_map[complement], i]
        num_map[num] = i
    # According to the problem description, a solution always exists,
    # so this part of the code should not be reached.
    return []

if __name__ == '__main__':
    # Test cases
    test_cases = [
        ([1, 2, 3], 4),
        ([1234, 5678, 9012], 14690),
        ([2, 2, 3], 4),
        ([3, 2, 4], 6),
        ([2, 7, 11, 15], 9)
    ]

    for i, (numbers, target) in enumerate(test_cases):
        result = two_sum(numbers, target)
        # Sort for consistent output format
        result.sort()
        print(f"Test Case {i + 1}:")
        print(f"Input: numbers = {numbers}, target = {target}")
        print(f"Output: {result}")
        print()