from collections import deque

def constrained_subset_sum(nums, k):
    n = len(nums)
    dp = [0] * n
    dq = deque()  # stores indices of dp in decreasing order
    ans = -10**18

    for i in range(n):
        while dq and i - dq[0] > k:
            dq.popleft()
        best_prev = 0 if not dq else max(0, dp[dq[0]])
        dp[i] = nums[i] + best_prev
        ans = max(ans, dp[i])
        if dp[i] > 0:
            while dq and dp[dq[-1]] <= dp[i]:
                dq.pop()
            dq.append(i)
    return ans

if __name__ == "__main__":
    tests = [
        ([10, 2, -10, 5, 20], 2),
        ([-1, -2, -3], 1),
        ([10, -2, -10, -5, 20], 2),
        ([1, -1, -1, -1, 5], 2),
        ([5, -1, -2, 10], 3),
    ]
    for nums, k in tests:
        print(constrained_subset_sum(nums, k))