
from typing import List

def find_median_sorted_arrays(nums1: List[int], nums2: List[int]) -> float:
    # Input validation
    if nums1 is None or nums2 is None:
        raise ValueError("Input arrays must not be None")
    
    if len(nums1) > 1000 or len(nums2) > 1000:
        raise ValueError("Array length must not exceed 1000")
    
    if len(nums1) + len(nums2) == 0:
        raise ValueError("At least one array must be non-empty")
    
    if len(nums1) + len(nums2) > 2000:
        raise ValueError("Combined length must not exceed 2000")
    
    # Ensure nums1 is the smaller array
    if len(nums1) > len(nums2):
        nums1, nums2 = nums2, nums1
    
    m, n = len(nums1), len(nums2)
    low, high = 0, m
    
    while low <= high:
        partition1 = (low + high) // 2
        partition2 = (m + n + 1) // 2 - partition1
        
        max_left1 = float('-inf') if partition1 == 0 else nums1[partition1 - 1]
        min_right1 = float('inf') if partition1 == m else nums1[partition1]
        
        max_left2 = float('-inf') if partition2 == 0 else nums2[partition2 - 1]
        min_right2 = float('inf') if partition2 == n else nums2[partition2]
        
        if max_left1 <= min_right2 and max_left2 <= min_right1:
            if (m + n) % 2 == 0:
                return (max(max_left1, max_left2) + min(min_right1, min_right2)) / 2.0
            else:
                return float(max(max_left1, max_left2))
        elif max_left1 > min_right2:
            high = partition1 - 1
        else:
            low = partition1 + 1
    
    raise ValueError("Input arrays are not sorted")

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", find_median_sorted_arrays([1, 3], [2]))
    
    # Test case 2
    print("Test 2:", find_median_sorted_arrays([1, 2], [3, 4]))
    
    # Test case 3
    print("Test 3:", find_median_sorted_arrays([], [1]))
    
    # Test case 4
    print("Test 4:", find_median_sorted_arrays([1, 2, 3, 4, 5], [6, 7, 8, 9, 10]))
    
    # Test case 5
    print("Test 5:", find_median_sorted_arrays([1], [2, 3, 4, 5]))
