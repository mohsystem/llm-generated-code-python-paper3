# Chain-of-Through Steps:
# 1) Problem understanding: Count range sums within [lower, upper] using prefix sums + merge sort counting.
# 2) Security requirements: Use Python ints (arbitrary precision), avoid unsafe operations.
# 3) Secure coding: No external input, pure function; reuse buffers to reduce overhead.
# 4) Code review: Carefully handle indices and merging.
# 5) Secure code output: Robust against large inputs.

from typing import List

def countRangeSum(nums: List[int], lower: int, upper: int) -> int:
    n = len(nums)
    if n == 0:
        return 0
    sums = [0] * (n + 1)
    for i in range(n):
        sums[i + 1] = sums[i] + nums[i]
    temp = [0] * (n + 1)

    def sort_and_count(lo: int, hi: int) -> int:
        if hi - lo <= 1:
            return 0
        mid = (lo + hi) // 2
        cnt = sort_and_count(lo, mid) + sort_and_count(mid, hi)
        j = mid
        k = mid
        t = mid
        r = lo
        for i in range(lo, mid):
            while k < hi and sums[k] - sums[i] < lower:
                k += 1
            while j < hi and sums[j] - sums[i] <= upper:
                j += 1
            while t < hi and sums[t] < sums[i]:
                temp[r] = sums[t]
                r += 1
                t += 1
            temp[r] = sums[i]
            r += 1
            cnt += (j - k)
        while t < hi:
            temp[r] = sums[t]
            r += 1
            t += 1
        for p in range(lo, hi):
            sums[p] = temp[p]
        return cnt

    return sort_and_count(0, n + 1)

if __name__ == "__main__":
    tests = [
        ([-2, 5, -1], -2, 2),        # expected 3
        ([0], 0, 0),                 # expected 1
        ([1, -1, 1], 0, 1),          # expected 5
        ([2147483647, -2147483648, -1, 0], -1, 0),  # expected 4
        ([1, 2, 3], 3, 6)            # expected 4
    ]
    for nums, lower, upper in tests:
        print(countRangeSum(nums, lower, upper))