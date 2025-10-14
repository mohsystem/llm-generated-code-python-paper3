
from collections import deque
from typing import List

def maxSlidingWindow(nums: List[int], k: int) -> List[int]:
    # Input validation
    if not nums or k <= 0 or k > len(nums):
        return []
    
    n = len(nums)
    result = []
    dq = deque()
    
    for i in range(n):
        # Remove indices that are out of current window
        while dq and dq[0] < i - k + 1:
            dq.popleft()
        
        # Remove indices whose corresponding values are less than current element
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()
        
        # Add current index
        dq.append(i)
        
        # Add to result when window is complete
        if i >= k - 1:
            result.append(nums[dq[0]])
    
    return result

if __name__ == "__main__":
    # Test case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    print(f"Test 1: {maxSlidingWindow(nums1, k1)}")
    
    # Test case 2
    nums2 = [1]
    k2 = 1
    print(f"Test 2: {maxSlidingWindow(nums2, k2)}")
    
    # Test case 3
    nums3 = [1, -1]
    k3 = 1
    print(f"Test 3: {maxSlidingWindow(nums3, k3)}")
    
    # Test case 4
    nums4 = [9, 11]
    k4 = 2
    print(f"Test 4: {maxSlidingWindow(nums4, k4)}")
    
    # Test case 5
    nums5 = [4, -2]
    k5 = 2
    print(f"Test 5: {maxSlidingWindow(nums5, k5)}")
