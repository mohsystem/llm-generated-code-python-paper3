import collections

class Task177:
  def constrainedSubsetSum(self, nums: list[int], k: int) -> int:
    n = len(nums)
    dp = [0] * n
    dq = collections.deque()
    max_sum = float('-inf')

    for i in range(n):
        # Remove indices from the front that are out of the window [i-k, i-1].
        if dq and dq[0] < i - k:
            dq.popleft()
        
        # Calculate dp[i]
        # The max sum from the previous k elements is at the front of the deque
        prev_max = dp[dq[0]] if dq else 0
        
        # If prev_max is negative, we start a new subsequence from nums[i]
        dp[i] = nums[i] + max(0, prev_max)

        # Maintain the monotonically decreasing property of the deque based on dp values.
        while dq and dp[i] >= dp[dq[-1]]:
            dq.pop()
        
        dq.append(i)
        
        max_sum = max(max_sum, dp[i])
        
    return max_sum

def main():
    solver = Task177()
    
    # Test Case 1
    nums1 = [10, 2, -10, 5, 20]
    k1 = 2
    print(f"Test Case 1: {solver.constrainedSubsetSum(nums1, k1)}")

    # Test Case 2
    nums2 = [-1, -2, -3]
    k2 = 1
    print(f"Test Case 2: {solver.constrainedSubsetSum(nums2, k2)}")

    # Test Case 3
    nums3 = [10, -2, -10, -5, 20]
    k3 = 2
    print(f"Test Case 3: {solver.constrainedSubsetSum(nums3, k3)}")

    # Test Case 4
    nums4 = [1, -2, 3, 4, -5, 6]
    k4 = 3
    print(f"Test Case 4: {solver.constrainedSubsetSum(nums4, k4)}")

    # Test Case 5
    nums5 = [-5, -4, -3, -2, -1]
    k5 = 5
    print(f"Test Case 5: {solver.constrainedSubsetSum(nums5, k5)}")

if __name__ == "__main__":
    main()