
from collections import deque

def constrained_subset_sum(nums, k):
    n = len(nums)
    dp = [0] * n
    dq = deque()
    max_sum = float('-inf')
    
    for i in range(n):
        # Remove elements outside the window
        while dq and dq[0] < i - k:
            dq.popleft()
        
        # Calculate dp[i]
        dp[i] = nums[i]
        if dq:
            dp[i] = max(dp[i], nums[i] + dp[dq[0]])
        
        # Maintain deque in decreasing order of dp values
        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        
        dq.append(i)
        max_sum = max(max_sum, dp[i])
    
    return max_sum

if __name__ == "__main__":
    # Test case 1
    nums1 = [10, 2, -10, 5, 20]
    k1 = 2
    print(f"Test 1: {constrained_subset_sum(nums1, k1)}")  # Expected: 37
    
    # Test case 2
    nums2 = [-1, -2, -3]
    k2 = 1
    print(f"Test 2: {constrained_subset_sum(nums2, k2)}")  # Expected: -1
    
    # Test case 3
    nums3 = [10, -2, -10, -5, 20]
    k3 = 2
    print(f"Test 3: {constrained_subset_sum(nums3, k3)}")  # Expected: 23
    
    # Test case 4
    nums4 = [1, 2, 3, 4, 5]
    k4 = 3
    print(f"Test 4: {constrained_subset_sum(nums4, k4)}")  # Expected: 15
    
    # Test case 5
    nums5 = [-5, -3, -1]
    k5 = 2
    print(f"Test 5: {constrained_subset_sum(nums5, k5)}")  # Expected: -1
