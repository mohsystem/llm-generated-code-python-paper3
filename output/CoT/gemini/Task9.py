def odd_or_even(arr):
    """
    Given a list of integers, determine whether the sum of its elements is odd or even.
    An empty list is treated as [0].
    """
    # The sum of an empty list is 0, which is even.
    total_sum = sum(arr)
    if total_sum % 2 == 0:
        return "even"
    else:
        return "odd"

# Main block with test cases
if __name__ == '__main__':
    # Test Case 1
    test1 = [0]
    print(f"Input: {test1}")
    print(f"Output: {odd_or_even(test1)}")  # Expected: even

    # Test Case 2
    test2 = [0, 1, 4]
    print(f"Input: {test2}")
    print(f"Output: {odd_or_even(test2)}")  # Expected: odd

    # Test Case 3
    test3 = [0, -1, -5]
    print(f"Input: {test3}")
    print(f"Output: {odd_or_even(test3)}")  # Expected: even
    
    # Test Case 4 (Empty list)
    test4 = []
    print(f"Input: {test4}")
    print(f"Output: {odd_or_even(test4)}")  # Expected: even

    # Test Case 5
    test5 = [1, 2, 3, 4, 5]
    print(f"Input: {test5}")
    print(f"Output: {odd_or_even(test5)}")  # Expected: odd