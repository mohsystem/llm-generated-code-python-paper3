
from collections import deque

def maxSlidingWindow(nums, k):
    if not nums or k <= 0:
        return []
    
    n = len(nums)
    result = []
    dq = deque()
    
    for i in range(n):
        # Remove elements outside the current window
        while dq and dq[0] < i - k + 1:
            dq.popleft()
        
        # Remove elements smaller than current element from the back
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()
        
        dq.append(i)
        
        # Add to result once we have a complete window
        if i >= k - 1:
            result.append(nums[dq[0]])
    
    return result

if __name__ == "__main__":
    # Test case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    print("Test 1:", maxSlidingWindow(nums1, k1))
    
    # Test case 2
    nums2 = [1]
    k2 = 1
    print("Test 2:", maxSlidingWindow(nums2, k2))
    
    # Test case 3
    nums3 = [1, -1]
    k3 = 1
    print("Test 3:", maxSlidingWindow(nums3, k3))
    
    # Test case 4
    nums4 = [9, 11]
    k4 = 2
    print("Test 4:", maxSlidingWindow(nums4, k4))
    
    # Test case 5
    nums5 = [4, -2, -1, 3, 5, 2]
    k5 = 2
    print("Test 5:", maxSlidingWindow(nums5, k5))
