from collections import deque
from typing import List

def constrained_subsequence_sum(nums: List[int], k: int) -> int:
    if not isinstance(nums, list):
        raise ValueError("nums must be a list of integers")
    if len(nums) == 0:
        raise ValueError("nums must be non-empty")
    if not isinstance(k, int) or k < 1 or k > len(nums):
        raise ValueError("k must satisfy 1 <= k <= len(nums)")
    # Optional: type check elements
    for x in nums:
        if not isinstance(x, int):
            raise ValueError("nums must contain integers only")

    n = len(nums)
    dp = [0] * n
    ans = -10**19  # sufficiently small
    dq: deque[int] = deque()

    for i in range(n):
        while dq and dq[0] < i - k:
            dq.popleft()
        best_prev = dp[dq[0]] if dq else 0
        if best_prev < 0:
            best_prev = 0
        dp[i] = nums[i] + best_prev
        if not dq:
            dq.append(i)
        else:
            while dq and dp[dq[-1]] <= dp[i]:
                dq.pop()
            dq.append(i)
        if dp[i] > ans:
            ans = dp[i]
    return ans

def _run_test(nums: List[int], k: int) -> None:
    res = constrained_subsequence_sum(nums, k)
    print(f"Result: {res}")

if __name__ == "__main__":
    # 5 test cases
    _run_test([10, 2, -10, 5, 20], 2)        # Expected 37
    _run_test([-1, -2, -3], 1)               # Expected -1
    _run_test([10, -2, -10, -5, 20], 2)      # Expected 23
    _run_test([5], 1)                        # Expected 5
    _run_test([1, -1, 1, -1, 1], 4)          # Expected 3