from typing import List

def count_range_sum(nums: List[int], lower: int, upper: int) -> int:
    if nums is None:
        raise ValueError("nums must not be None")
    n = len(nums)
    if not (1 <= n <= 100000):
        raise ValueError("nums length out of allowed range")
    if lower > upper:
        raise ValueError("lower must be <= upper")
    if lower < -100000 or upper > 100000:
        raise ValueError("lower/upper out of allowed range")

    sums = [0]
    for v in nums:
        sums.append(sums[-1] + int(v))

    temp = [0] * len(sums)

    def sort_count(arr: List[int], left: int, right: int) -> int:
        if right - left <= 1:
            return 0
        mid = (left + right) // 2
        cnt = sort_count(arr, left, mid) + sort_count(arr, mid, right)
        lo = hi = mid
        for i in range(left, mid):
            while lo < right and arr[lo] - arr[i] < lower:
                lo += 1
            while hi < right and arr[hi] - arr[i] <= upper:
                hi += 1
            cnt += hi - lo
        # merge
        i, j, k = left, mid, left
        while i < mid or j < right:
            if j >= right or (i < mid and arr[i] <= arr[j]):
                temp[k] = arr[i]
                i += 1
            else:
                temp[k] = arr[j]
                j += 1
            k += 1
        for i in range(left, right):
            arr[i] = temp[i]
        return cnt

    return int(sort_count(sums, 0, len(sums)))


def _run_test(nums: List[int], lower: int, upper: int, expected: int) -> None:
    res = count_range_sum(nums, lower, upper)
    print(f"Result: {res} | Expected: {expected}")


if __name__ == "__main__":
    # Five test cases
    _run_test([-2, 5, -1], -2, 2, 3)
    _run_test([0], 0, 0, 1)
    _run_test([1, 2, 3], 3, 6, 4)
    _run_test([-1, -1, -1], -3, -1, 6)
    _run_test([1, -1, 1, -1], 0, 0, 4)