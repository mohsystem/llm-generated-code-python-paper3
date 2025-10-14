from typing import List

def count_range_sum(nums: List[int], lower: int, upper: int) -> int:
    n = len(nums)
    prefix = [0] * (n + 1)
    for i in range(n):
        prefix[i + 1] = prefix[i] + nums[i]

    temp = [0] * (n + 1)

    def sort_count(left: int, right: int) -> int:
        if right - left <= 1:
            return 0
        mid = (left + right) // 2
        count = sort_count(left, mid) + sort_count(mid, right)

        j = k = r = mid
        p = left
        for i in range(left, mid):
            while j < right and prefix[j] - prefix[i] < lower:
                j += 1
            while k < right and prefix[k] - prefix[i] <= upper:
                k += 1
            count += k - j
            while r < right and prefix[r] < prefix[i]:
                temp[p] = prefix[r]
                p += 1
                r += 1
            temp[p] = prefix[i]
            p += 1
        while r < right:
            temp[p] = prefix[r]
            p += 1
            r += 1
        for i in range(left, right):
            prefix[i] = temp[i]
        return count

    return sort_count(0, n + 1)

if __name__ == "__main__":
    tests = [
        ([-2, 5, -1], -2, 2),
        ([0], 0, 0),
        ([1, 2, 3, 4], 3, 6),
        ([-1, -1, -1], -2, -1),
        ([0, 0, 0, 0], 0, 0),
    ]
    for nums, lo, up in tests:
        print(count_range_sum(nums, lo, up))