from collections import deque

def constrained_subset_sum(nums, k):
    if not isinstance(nums, list) or len(nums) == 0 or k <= 0:
        return 0
    n = len(nums)
    dp = [0] * n
    dq = deque()
    ans = None
    for i in range(n):
        while dq and dq[0] < i - k:
            dq.popleft()
        best = dp[dq[0]] if dq else 0
        dp[i] = nums[i] + (best if best > 0 else 0)
        ans = dp[i] if ans is None else max(ans, dp[i])
        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        dq.append(i)
    return ans if ans is not None else 0

def _run_tests():
    tests = [
        ([10, 2, -10, 5, 20], 2),
        ([-1, -2, -3], 1),
        ([10, -2, -10, -5, 20], 2),
        ([1, -1, -2, 4, -7, 3], 2),
        ([5, -1, 5], 1),
    ]
    for nums, k in tests:
        print(constrained_subset_sum(nums, k))

if __name__ == "__main__":
    _run_tests()