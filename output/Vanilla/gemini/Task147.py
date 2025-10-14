def find_kth_largest(nums, k):
    """
    Finds the kth largest element in an array.
    """
    # Sort the list in ascending order
    nums.sort()
    # The kth largest element is at index len(nums) - k
    return nums[len(nums) - k]

if __name__ == "__main__":
    # Test Case 1
    nums1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test Case 1: {find_kth_largest(nums1, k1)}")

    # Test Case 2
    nums2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test Case 2: {find_kth_largest(nums2, k2)}")

    # Test Case 3
    nums3 = [1]
    k3 = 1
    print(f"Test Case 3: {find_kth_largest(nums3, k3)}")

    # Test Case 4
    nums4 = [7, 6, 5, 4, 3, 2, 1]
    k4 = 7
    print(f"Test Case 4: {find_kth_largest(nums4, k4)}")

    # Test Case 5
    nums5 = [-1, -1, 0, 2]
    k5 = 3
    print(f"Test Case 5: {find_kth_largest(nums5, k5)}")