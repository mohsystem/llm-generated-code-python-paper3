def odd_or_even(arr):
    """
    Given a list of integers, determine whether the sum of its elements is odd or even.
    An empty list is treated as [0].
    """
    # The sum of an empty list in Python is 0, which correctly handles the edge case.
    total = sum(arr)
    if total % 2 == 0:
        return "even"
    else:
        return "odd"
    # Alternative one-liner:
    # return 'even' if sum(arr) % 2 == 0 else 'odd'

# Main block with test cases
if __name__ == '__main__':
    # Test Case 1
    arr1 = [0]
    print(f"Input: {arr1}, Output: {odd_or_even(arr1)}")

    # Test Case 2
    arr2 = [0, 1, 4]
    print(f"Input: {arr2}, Output: {odd_or_even(arr2)}")

    # Test Case 3
    arr3 = [0, -1, -5]
    print(f"Input: {arr3}, Output: {odd_or_even(arr3)}")

    # Test Case 4: Empty list
    arr4 = []
    print(f"Input: {arr4}, Output: {odd_or_even(arr4)}")

    # Test Case 5
    arr5 = [1, 2, 3, 4, 5]
    print(f"Input: {arr5}, Output: {odd_or_even(arr5)}")