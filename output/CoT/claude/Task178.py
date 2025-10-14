
from collections import deque
from typing import List

def shortest_subarray(nums: List[int], k: int) -> int:
    if not nums:
        return -1
    
    n = len(nums)
    prefix_sum = [0] * (n + 1)
    
    # Calculate prefix sums
    for i in range(n):
        prefix_sum[i + 1] = prefix_sum[i] + nums[i]
    
    min_length = float('inf')
    dq = deque()
    
    for i in range(n + 1):
        # Remove indices from front where sum >= k
        while dq and prefix_sum[i] - prefix_sum[dq[0]] >= k:
            min_length = min(min_length, i - dq.popleft())
        
        # Maintain monotonic increasing deque
        while dq and prefix_sum[i] <= prefix_sum[dq[-1]]:
            dq.pop()
        
        dq.append(i)
    
    return min_length if min_length != float('inf') else -1

if __name__ == "__main__":
    # Test case 1
    nums1 = [1]
    k1 = 1
    print(f"Test 1: {shortest_subarray(nums1, k1)}")  # Expected: 1
    
    # Test case 2
    nums2 = [1, 2]
    k2 = 4
    print(f"Test 2: {shortest_subarray(nums2, k2)}")  # Expected: -1
    
    # Test case 3
    nums3 = [2, -1, 2]
    k3 = 3
    print(f"Test 3: {shortest_subarray(nums3, k3)}")  # Expected: 3
    
    # Test case 4
    nums4 = [84, -37, 32, 40, 95]
    k4 = 167
    print(f"Test 4: {shortest_subarray(nums4, k4)}")  # Expected: 3
    
    # Test case 5
    nums5 = [-28, 81, -20, 28, -29]
    k5 = 89
    print(f"Test 5: {shortest_subarray(nums5, k5)}")  # Expected: 3
