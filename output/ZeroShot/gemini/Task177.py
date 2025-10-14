import collections
from typing import List

def constrainedSubsetSum(nums: List[int], k: int) -> int:
    """
    Finds the maximum sum of a non-empty subsequence of the array `nums`
    such that for every two consecutive integers in the subsequence, nums[i] and nums[j],
    where i < j, the condition j - i <= k is satisfied.

    :param nums: The input integer list.
    :param k: The maximum distance between indices of consecutive elements in the subsequence.
    :return: The maximum subsequence sum.
    """
    if not nums:
        return 0

    n = len(nums)
    # dp[i] will store the maximum subsequence sum ending at index i.
    dp = [0] * n
    # Deque will store indices `j` such that dp[j] are in decreasing order.
    dq = collections.deque()
    max_sum = -float('inf')

    for i in range(n):
        # 1. Remove indices from the front of the deque that are out of the window [i-k, i-1].
        if dq and dq[0] < i - k:
            dq.popleft()
        
        # 2. Calculate dp[i]. The max sum of a valid subsequence ending before i
        #    is at the front of the deque.
        max_prev = 0
        if dq:
            max_prev = dp[dq[0]]
        
        # If max_prev is negative, we start a new subsequence from nums[i].
        dp[i] = nums[i] + max(0, max_prev)
        
        # 3. Maintain the decreasing property of dp values in the deque.
        #    If dp[i] is greater than dp values at the end of the deque,
        #    those smaller values can never be the maximum in any future window.
        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        
        dq.append(i)
        
        # 4. Update the overall maximum sum found so far.
        max_sum = max(max_sum, dp[i])
        
    return max_sum

# main function with 5 test cases
if __name__ == '__main__':
    # Test Case 1
    nums1 = [10, 2, -10, 5, 20]
    k1 = 2
    print(f"Test Case 1: {constrainedSubsetSum(nums1, k1)}")  # Expected: 37

    # Test Case 2
    nums2 = [-1, -2, -3]
    k2 = 1
    print(f"Test Case 2: {constrainedSubsetSum(nums2, k2)}")  # Expected: -1

    # Test Case 3
    nums3 = [10, -2, -10, -5, 20]
    k3 = 2
    print(f"Test Case 3: {constrainedSubsetSum(nums3, k3)}")  # Expected: 23

    # Test Case 4
    nums4 = [-5, -6]
    k4 = 2
    print(f"Test Case 4: {constrainedSubsetSum(nums4, k4)}")  # Expected: -5

    # Test Case 5
    nums5 = [1, -5, -6, 2, 8, -4, 3]
    k5 = 3
    print(f"Test Case 5: {constrainedSubsetSum(nums5, k5)}")  # Expected: 14