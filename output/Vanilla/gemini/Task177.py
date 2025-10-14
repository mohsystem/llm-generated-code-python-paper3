import collections

def constrainedSubsetSum(nums, k):
    """
    :type nums: List[int]
    :type k: int
    :rtype: int
    """
    n = len(nums)
    # dp[i] will store the maximum sum of a subsequence ending at index i
    dp = [0] * n
    # A deque to store indices of dp elements, maintaining them in decreasing order of their values
    dq = collections.deque()
    max_sum = -float('inf')

    for i in range(n):
        # Remove indices from the front of the deque that are out of the k-sized window
        while dq and dq[0] < i - k:
            dq.popleft()

        # The max sum of a subsequence ending in the previous window is at the front of the deque
        prev_max = dp[dq[0]] if dq else 0
        
        # Calculate dp[i]: it's nums[i] plus the max sum from the previous valid subsequence.
        # If the previous max sum is negative, we start a new subsequence from nums[i].
        dp[i] = nums[i] + max(0, prev_max)

        # Maintain the deque in decreasing order of dp values
        # Remove elements from the back of the deque that are smaller than the current dp[i]
        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        
        # Add the current index to the deque
        dq.append(i)

        # Update the overall maximum sum found so far
        max_sum = max(max_sum, dp[i])

    return max_sum

# Main part for testing
if __name__ == "__main__":
    # Test Case 1
    nums1 = [10, 2, -10, 5, 20]
    k1 = 2
    print(f"Test Case 1: {constrainedSubsetSum(nums1, k1)}")

    # Test Case 2
    nums2 = [-1, -2, -3]
    k2 = 1
    print(f"Test Case 2: {constrainedSubsetSum(nums2, k2)}")

    # Test Case 3
    nums3 = [10, -2, -10, -5, 20]
    k3 = 2
    print(f"Test Case 3: {constrainedSubsetSum(nums3, k3)}")

    # Test Case 4
    nums4 = [-5, -4, -3, -2, -1]
    k4 = 3
    print(f"Test Case 4: {constrainedSubsetSum(nums4, k4)}")

    # Test Case 5
    nums5 = [1, -5, 2, -6, 3, -7, 4]
    k5 = 2
    print(f"Test Case 5: {constrainedSubsetSum(nums5, k5)}")