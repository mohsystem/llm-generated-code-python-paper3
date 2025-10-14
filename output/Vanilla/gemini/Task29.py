from typing import List, Tuple, Optional

def two_sum(numbers: List[int], target: int) -> Optional[Tuple[int, int]]:
    """
    Finds two indices of numbers in a list that add up to a target value.
    
    :param numbers: The input list of integers.
    :param target: The target sum.
    :return: A tuple of two integers representing the indices of the two numbers.
    """
    num_map = {}
    for i, num in enumerate(numbers):
        complement = target - num
        if complement in num_map:
            return (num_map[complement], i)
        num_map[num] = i
    # According to the problem description, a solution always exists.
    return None

if __name__ == '__main__':
    # Test Case 1
    print(f"Test 1: {two_sum([1, 2, 3], 4)}") # Expected: (0, 2)

    # Test Case 2
    print(f"Test 2: {two_sum([1234, 5678, 9012], 14690)}") # Expected: (1, 2)

    # Test Case 3
    print(f"Test 3: {two_sum([2, 2, 3], 4)}") # Expected: (0, 1)

    # Test Case 4
    print(f"Test 4: {two_sum([3, 2, 4], 6)}") # Expected: (1, 2)
    
    # Test Case 5
    print(f"Test 5: {two_sum([2, 7, 11, 15], 9)}") # Expected: (0, 1)