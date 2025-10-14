
from collections import deque
from typing import List

def constrained_subset_sum(nums: List[int], k: int) -> int:
    if not nums:
        raise ValueError("Array must not be empty")
    if k < 1 or k > len(nums):
        raise ValueError("k must be between 1 and array length")
    
    n = len(nums)
    dp = [0] * n
    dq = deque()
    max_sum = float('-inf')
    
    for i in range(n):
        # Remove elements outside the window of size k
        while dq and dq[0] < i - k:
            dq.popleft()
        
        # Calculate dp[i]
        dp[i] = nums[i]
        if dq:
            dp[i] = max(dp[i], nums[i] + dp[dq[0]])
        
        # Maintain decreasing order in deque
        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        dq.append(i)
        
        max_sum = max(max_sum, dp[i])
    
    return max_sum

def main():
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
    nums4 = [-5, -1, -8, -9]
    k4 = 3
    print(f"Test 4: {constrained_subset_sum(nums4, k4)}")  # Expected: -1
    
    # Test case 5
    nums5 = [1, 2, 3, 4, 5]
    k5 = 1
    print(f"Test 5: {constrained_subset_sum(nums5, k5)}")  # Expected: 15

if __name__ == "__main__":
    main()
