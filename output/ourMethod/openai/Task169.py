from bisect import bisect_left
from typing import List

def count_smaller(nums: List[int]) -> List[int]:
    if nums is None:
        raise ValueError("Input array is None.")
    n = len(nums)
    if n < 0 or n > 100000:
        raise ValueError("Invalid array length.")
    MIN_VAL, MAX_VAL = -10000, 10000
    for v in nums:
        if v < MIN_VAL or v > MAX_VAL:
            raise ValueError("Value out of allowed range.")
    if n == 0:
        return []

    # Coordinate compression
    uniq = sorted(set(nums))
    m = len(uniq)
    bit = [0] * (m + 2)

    def add(i: int, delta: int) -> None:
        while i < len(bit):
            bit[i] += delta
            i += i & -i

    def query(i: int) -> int:
        s = 0
        while i > 0:
            s += bit[i]
            i -= i & -i
        return s

    res = [0] * n
    for i in range(n - 1, -1, -1):
        idx = bisect_left(uniq, nums[i]) + 1  # 1-based
        res[i] = query(idx - 1)
        add(idx, 1)
    return res

def _print(arr: List[int]) -> None:
    print("[" + ",".join(str(x) for x in arr) + "]")

if __name__ == "__main__":
    tests = [
        [5, 2, 6, 1],
        [-1],
        [-1, -1],
        [1, 2, 3],
        [3, 2, 1],
    ]
    for t in tests:
        ans = count_smaller(t)
        _print(ans)