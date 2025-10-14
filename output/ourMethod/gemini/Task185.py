import math
from typing import List

def find_median_sorted_arrays(nums1: List[int], nums2: List[int]) -> float:
    if len(nums1) > len(nums2):
        return find_median_sorted_arrays(nums2, nums1)

    m, n = len(nums1), len(nums2)
    low, high = 0, m

    while low <= high:
        partition_x = (low + high) // 2
        partition_y = (m + n + 1) // 2 - partition_x

        max_left_x = nums1[partition_x - 1] if partition_x != 0 else -math.inf
        min_right_x = nums1[partition_x] if partition_x != m else math.inf

        max_left_y = nums2[partition_y - 1] if partition_y != 0 else -math.inf
        min_right_y = nums2[partition_y] if partition_y != n else math.inf

        if max_left_x <= min_right_y and max_left_y <= min_right_x:
            if (m + n) % 2 == 0:
                return (max(max_left_x, max_left_y) + min(min_right_x, min_right_y)) / 2.0
            else:
                return float(max(max_left_x, max_left_y))
        elif max_left_x > min_right_y:
            high = partition_x - 1
        else:
            low = partition_x + 1
    
    raise ValueError("Input arrays are invalid.")

if __name__ == '__main__':
    # Test Case 1
    nums1_1 = [1, 3]
    nums2_1 = [2]
    print(f"Test Case 1: {find_median_sorted_arrays(nums1_1, nums2_1)}")

    # Test Case 2
    nums1_2 = [1, 2]
    nums2_2 = [3, 4]
    print(f"Test Case 2: {find_median_sorted_arrays(nums1_2, nums2_2)}")

    # Test Case 3
    nums1_3 = [0, 0]
    nums2_3 = [0, 0]
    print(f"Test Case 3: {find_median_sorted_arrays(nums1_3, nums2_3)}")

    # Test Case 4
    nums1_4 = []
    nums2_4 = [1]
    print(f"Test Case 4: {find_median_sorted_arrays(nums1_4, nums2_4)}")

    # Test Case 5
    nums1_5 = [2]
    nums2_5 = []
    print(f"Test Case 5: {find_median_sorted_arrays(nums1_5, nums2_5)}")