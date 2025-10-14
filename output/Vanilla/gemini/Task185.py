import sys

def find_median_sorted_arrays(nums1, nums2):
    """
    Finds the median of two sorted arrays.
    """
    if len(nums1) > len(nums2):
        nums1, nums2 = nums2, nums1

    m, n = len(nums1), len(nums2)
    low, high = 0, m

    while low <= high:
        partitionX = low + (high - low) // 2
        partitionY = (m + n + 1) // 2 - partitionX

        maxLeftX = float('-inf') if partitionX == 0 else nums1[partitionX - 1]
        minRightX = float('inf') if partitionX == m else nums1[partitionX]

        maxLeftY = float('-inf') if partitionY == 0 else nums2[partitionY - 1]
        minRightY = float('inf') if partitionY == n else nums2[partitionY]

        if maxLeftX <= minRightY and maxLeftY <= minRightX:
            if (m + n) % 2 == 0:
                return (max(maxLeftX, maxLeftY) + min(minRightX, minRightY)) / 2.0
            else:
                return float(max(maxLeftX, maxLeftY))
        elif maxLeftX > minRightY:
            high = partitionX - 1
        else:
            low = partitionX + 1
    
    # This should not be reached for valid sorted array inputs
    raise ValueError("Input arrays are not sorted.")

if __name__ == '__main__':
    # Test Case 1
    nums1_1 = [1, 3]
    nums1_2 = [2]
    result1 = find_median_sorted_arrays(nums1_1, nums1_2)
    print(f"Test Case 1: {result1:.5f}")

    # Test Case 2
    nums2_1 = [1, 2]
    nums2_2 = [3, 4]
    result2 = find_median_sorted_arrays(nums2_1, nums2_2)
    print(f"Test Case 2: {result2:.5f}")

    # Test Case 3
    nums3_1 = [0, 0]
    nums3_2 = [0, 0]
    result3 = find_median_sorted_arrays(nums3_1, nums3_2)
    print(f"Test Case 3: {result3:.5f}")

    # Test Case 4
    nums4_1 = []
    nums4_2 = [1]
    result4 = find_median_sorted_arrays(nums4_1, nums4_2)
    print(f"Test Case 4: {result4:.5f}")

    # Test Case 5
    nums5_1 = [2]
    nums5_2 = []
    result5 = find_median_sorted_arrays(nums5_1, nums5_2)
    print(f"Test Case 5: {result5:.5f}")