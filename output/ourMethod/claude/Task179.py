
from typing import List
from collections import deque

def max_sliding_window(nums: List[int], k: int) -> List[int]:
    # Input validation
    if not nums or k <= 0 or k > len(nums):
        return []
    
    n = len(nums)
    result = []
    dq = deque()
    
    for i in range(n):
        # Remove indices that are out of the current window
        while dq and dq[0] < i - k + 1:
            dq.popleft()
        
        # Remove indices whose values are less than current value
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()
        
        dq.append(i)
        
        # Add to result when window is complete
        if i >= k - 1:
            result.append(nums[dq[0]])
    
    return result

def main():
    # Test case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    result1 = max_sliding_window(nums1, k1)
    print(f"Test 1: {result1}")
    
    # Test case 2
    nums2 = [1]
    k2 = 1
    result2 = max_sliding_window(nums2, k2)
    print(f"Test 2: {result2}")
    
    # Test case 3
    nums3 = [1, -1]
    k3 = 1
    result3 = max_sliding_window(nums3, k3)
    print(f"Test 3: {result3}")
    
    # Test case 4
    nums4 = [9, 11]
    k4 = 2
    result4 = max_sliding_window(nums4, k4)
    print(f"Test 4: {result4}")
    
    # Test case 5
    nums5 = [4, -2]
    k5 = 2
    result5 = max_sliding_window(nums5, k5)
    print(f"Test 5: {result5}")

if __name__ == "__main__":
    main()
