from collections import deque
from typing import List


def shortest_subarray(nums: List[int], k: int) -> int:
    if not isinstance(nums, list) or not all(isinstance(x, int) for x in nums):
        return -1
    n = len(nums)
    if n == 0 or n > 1_000_000:
        return -1
    if not isinstance(k, int):
        return -1

    prefix = [0] * (n + 1)
    for i in range(n):
        prefix[i + 1] = prefix[i] + nums[i]

    ans = n + 1
    dq: deque[int] = deque()
    for i in range(n + 1):
        while dq and prefix[i] - prefix[dq[0]] >= k:
            ans = min(ans, i - dq.popleft())
        while dq and prefix[i] <= prefix[dq[-1]]:
            dq.pop()
        dq.append(i)

    return ans if ans <= n else -1


def main() -> None:
    tests = [
        ([1], 1),
        ([1, 2], 4),
        ([2, -1, 2], 3),
        ([84, -37, 32, 40, 95], 167),
        ([17, 85, 93, -45, -21], 150),
    ]
    for idx, (arr, k) in enumerate(tests, 1):
        print(f"Test {idx} nums={arr} k={k} -> {shortest_subarray(arr, k)}")


if __name__ == "__main__":
    main()