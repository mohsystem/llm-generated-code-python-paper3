from collections import deque
from typing import List


def max_sliding_window(nums: List[int], k: int) -> List[int]:
    if not isinstance(nums, list) or not isinstance(k, int):
        return []
    n = len(nums)
    if n == 0 or k <= 0 or k > n:
        return []
    dq: deque[int] = deque()  # store indices; values decreasing
    res: List[int] = []
    for i, v in enumerate(nums):
        while dq and dq[0] <= i - k:
            dq.popleft()
        while dq and nums[dq[-1]] <= v:
            dq.pop()
        dq.append(i)
        if i >= k - 1:
            res.append(nums[dq[0]])
    return res


def _run_test(nums: List[int], k: int, expected: List[int]) -> None:
    out = max_sliding_window(nums, k)
    print(f"nums={nums}, k={k}")
    print(f"out ={out}")
    print(f"exp ={expected}")
    print("---")


if __name__ == "__main__":
    _run_test([1,3,-1,-3,5,3,6,7], 3, [3,3,5,5,6,7])
    _run_test([1], 1, [1])
    _run_test([9,8,7,6], 4, [9])
    _run_test([1,2,3,4,5], 2, [2,3,4,5])
    _run_test([5,4,3,2,1], 2, [5,4,3,2])