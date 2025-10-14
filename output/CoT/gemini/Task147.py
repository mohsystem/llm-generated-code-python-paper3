def find_kth_largest(nums, k):
    """
    Finds the kth largest element in a list of integers.
    This function sorts the list and picks the element from the end.

    Args:
        nums: A list of integers.
        k: The position 'k' of the largest element to find (1-based index).

    Returns:
        The integer value of the kth largest element, or None if the input is invalid.
    """
    # Security: Validate inputs to prevent index errors and handle invalid arguments.
    if not nums or k <= 0 or k > len(nums):
        return None

    # Sort the list in ascending order. This creates a sorted copy.
    # Time complexity is O(N log N).
    sorted_nums = sorted(nums)

    # The kth largest element is at index (length - k) in a 0-indexed list
    # sorted in ascending order.
    return sorted_nums[len(sorted_nums) - k]

if __name__ == "__main__":
    # Test Case 1: General case
    nums1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test Case 1: Array = {nums1}, k = {k1}")
    print(f"Result: {find_kth_largest(nums1, k1)}") # Expected: 5
    print("-" * 20)

    # Test Case 2: With duplicates
    nums2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test Case 2: Array = {nums2}, k = {k2}")
    print(f"Result: {find_kth_largest(nums2, k2)}") # Expected: 4
    print("-" * 20)

    # Test Case 3: k = 1 (the largest element)
    nums3 = [7, 6, 5, 4, 3, 2, 1]
    k3 = 1
    print(f"Test Case 3: Array = {nums3}, k = {k3}")
    print(f"Result: {find_kth_largest(nums3, k3)}") # Expected: 7
    print("-" * 20)

    # Test Case 4: k = n (the smallest element)
    nums4 = [7, 6, 5, 4, 3, 2, 1]
    k4 = 7
    print(f"Test Case 4: Array = {nums4}, k = {k4}")
    print(f"Result: {find_kth_largest(nums4, k4)}") # Expected: 1
    print("-" * 20)

    # Test Case 5: Invalid k (k > length of array)
    nums5 = [1, 2]
    k5 = 3
    print(f"Test Case 5: Array = {nums5}, k = {k5}")
    result5 = find_kth_largest(nums5, k5)
    print(f"Result: {'Invalid input' if result5 is None else result5}") # Expected: Invalid input
    print("-" * 20)