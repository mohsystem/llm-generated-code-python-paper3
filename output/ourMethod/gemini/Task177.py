import collections
from typing import List

def constrained_subset_sum(nums: List[int], k: int) -> int:
    """
    Calculates the maximum sum of a non-empty subsequence of the array
    such that for every two consecutive integers in the subsequence,
    nums[i] and nums[j] with i < j, the condition j - i <= k is satisfied.

    :param nums: The input integer list.
    :param k: The constraint for the distance between consecutive indices.
    :return: The maximum constrained subsequence sum.
    """
    if not nums:
        return 0
    
    n = len(nums)
    # dp[i] will store the max sum of a subsequence ending at index i
    dp = [0] * n
    # Deque to store indices for the sliding window maximum
    deque = collections.deque()
    max_sum = float('-inf')

    for i in range(n):
        # Remove indices from the front that are out of the window [i-k, i-1]
        if deque and deque[0] < i - k:
            deque.popleft()

        # Calculate dp[i]. The max sum from the previous valid window is at the front of the deque.
        prev_max = 0
        if deque:
            prev_max = dp[deque[0]]
        
        # If prev_max is positive, extend the subsequence. Otherwise, start a new one.
        dp[i] = nums[i] + max(0, prev_max)

        # Maintain the decreasing property of the deque (in terms of dp values)
        while deque and dp[deque[-1]] <= dp[i]:
            deque.pop()
        
        deque.append(i)

        # Update the overall maximum sum found so far
        max_sum = max(max_sum, dp[i])
        
    return max_sum

if __name__ == '__main__':
    # Test Case 1
    nums1 = [10, 2, -10, 5, 20]
    k1 = 2
    print(f"Test Case 1: {constrained_subset_sum(nums1, k1)}")

    # Test Case 2
    nums2 = [-1, -2, -3]
    k2 = 1
    print(f"Test Case 2: {constrained_subset_sum(nums2, k2)}")

    # Test Case 3
    nums3 = [10, -2, -10, -5, 20]
    k3 = 2
    print(f"Test Case 3: {constrained_subset_sum(nums3, k3)}")

    # Test Case 4
    nums4 = [-8269, 3217, -4023, -4138, -683, 6455, -3621, 9242, 4015, -3790]
    k4 = 1
    print(f"Test Case 4: {constrained_subset_sum(nums4, k4)}")
    
    # Test Case 5
    nums5 = [1, -1, -2, -3, 5]
    k5 = 2
    print(f"Test Case 5: {constrained_subset_sum(nums5, k5)}")