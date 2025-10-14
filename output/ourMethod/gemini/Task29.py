from typing import List, Tuple

def two_sum(numbers: List[int], target: int) -> Tuple[int, int]:
    """
    Finds two different items in the list that sum up to the target value.

    :param numbers: The input list of integers. Must have at least 2 elements.
    :param target: The target integer value.
    :return: A tuple of two integers representing the indices of the two numbers.
    """
    num_map = {}
    for i, num in enumerate(numbers):
        complement = target - num
        if complement in num_map:
            return (num_map[complement], i)
        num_map[num] = i
    # Per problem description, a valid solution always exists.
    # Returning an empty tuple or raising an exception would be for a more general case.
    return ()

if __name__ == '__main__':
    # Test case 1
    nums1 = [1, 2, 3]
    target1 = 4
    result1 = two_sum(nums1, target1)
    print(f"Test Case 1: {result1}")  # Expected: (0, 2)

    # Test case 2
    nums2 = [1234, 5678, 9012]
    target2 = 14690
    result2 = two_sum(nums2, target2)
    print(f"Test Case 2: {result2}")  # Expected: (1, 2)

    # Test case 3
    nums3 = [2, 2, 3]
    target3 = 4
    result3 = two_sum(nums3, target3)
    print(f"Test Case 3: {result3}")  # Expected: (0, 1)
    
    # Test case 4
    nums4 = [3, 2, 4]
    target4 = 6
    result4 = two_sum(nums4, target4)
    print(f"Test Case 4: {result4}")  # Expected: (1, 2)

    # Test case 5
    nums5 = [3, 3]
    target5 = 6
    result5 = two_sum(nums5, target5)
    print(f"Test Case 5: {result5}")  # Expected: (0, 1)