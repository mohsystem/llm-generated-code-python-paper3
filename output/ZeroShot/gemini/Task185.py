from typing import List

def findMedianSortedArrays(nums1: List[int], nums2: List[int]) -> float:
    """
    Finds the median of two sorted arrays.
    The overall run time complexity is O(log(min(m, n))).
    """
    # Ensure nums1 is the smaller array to optimize binary search
    if len(nums1) > len(nums2):
        nums1, nums2 = nums2, nums1

    m, n = len(nums1), len(nums2)
    low, high = 0, m
    
    # The total number of elements in the left partition
    half_len = (m + n + 1) // 2

    while low <= high:
        # partitionX is the number of elements from nums1 in the left partition
        partitionX = (low + high) // 2
        partitionY = half_len - partitionX

        # Get the boundary elements for the partitions
        maxLeftX = float('-inf') if partitionX == 0 else nums1[partitionX - 1]
        minRightX = float('inf') if partitionX == m else nums1[partitionX]

        maxLeftY = float('-inf') if partitionY == 0 else nums2[partitionY - 1]
        minRightY = float('inf') if partitionY == n else nums2[partitionY]

        if maxLeftX <= minRightY and maxLeftY <= minRightX:
            # Correct partition found, calculate the median
            if (m + n) % 2 == 0:
                # Even number of total elements
                return (max(maxLeftX, maxLeftY) + min(minRightX, minRightY)) / 2.0
            else:
                # Odd number of total elements
                return float(max(maxLeftX, maxLeftY))
        elif maxLeftX > minRightY:
            # partitionX is too large, move left
            high = partitionX - 1
        else:
            # partitionX is too small, move right
            low = partitionX + 1
            
    # This part should not be reached if the input arrays are sorted
    raise ValueError("Input arrays are not sorted or are invalid.")

if __name__ == "__main__":
    # Test Case 1
    nums1_1 = [1, 3]
    nums2_1 = [2]
    print(f"Test Case 1: {findMedianSortedArrays(nums1_1, nums2_1):.5f}")

    # Test Case 2
    nums1_2 = [1, 2]
    nums2_2 = [3, 4]
    print(f"Test Case 2: {findMedianSortedArrays(nums1_2, nums2_2):.5f}")

    # Test Case 3
    nums1_3 = [0, 0]
    nums2_3 = [0, 0]
    print(f"Test Case 3: {findMedianSortedArrays(nums1_3, nums2_3):.5f}")

    # Test Case 4
    nums1_4 = []
    nums2_4 = [1]
    print(f"Test Case 4: {findMedianSortedArrays(nums1_4, nums2_4):.5f}")

    # Test Case 5
    nums1_5 = [2]
    nums2_5 = []
    print(f"Test Case 5: {findMedianSortedArrays(nums1_5, nums2_5):.5f}")