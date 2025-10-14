from collections import deque

def constrained_subsequence_sum(nums, k):
    if not nums or k <= 0:
        raise ValueError("Invalid input")
    n = len(nums)
    dp = [0] * n
    ans = float('-inf')
    dq = deque()  # store indices with decreasing dp values

    for i in range(n):
        while dq and dq[0] < i - k:
            dq.popleft()
        best_prev = dp[dq[0]] if dq and dp[dq[0]] > 0 else 0
        dp[i] = nums[i] + best_prev
        ans = max(ans, dp[i])

        while dq and dp[dq[-1]] <= dp[i]:
            dq.pop()
        dq.append(i)

    return ans

if __name__ == "__main__":
    tests = [
        ([10, 2, -10, 5, 20], 2),
        ([-1, -2, -3], 1),
        ([10, -2, -10, -5, 20], 2),
        ([1, -1, -2, 4, -7, 3], 2),
        ([-5], 1),
    ]
    expected = [37, -1, 23, 7, -5]
    for idx, ((arr, k), exp) in enumerate(zip(tests, expected), 1):
        res = constrained_subsequence_sum(arr, k)
        print(f"Result {idx}: {res} (Expected: {exp})")