# Chain-of-Through:
# 1) Understand: count pairs (i<j) with nums[i] > 2*nums[j]
# 2) Security: handle None, safe ints in Python
# 3) Secure coding: no global state, stable merge
# 4) Review: comparisons use Python ints (unbounded)
# 5) Output: 5 test cases

from typing import List

def reverse_pairs(nums: List[int]) -> int:
    if nums is None or len(nums) < 2:
        return 0

    def sort_count(a, l, r, temp):
        if l >= r:
            return 0
        m = l + (r - l) // 2
        cnt = sort_count(a, l, m, temp)
        cnt += sort_count(a, m + 1, r, temp)
        cnt += count_pairs(a, l, m, r)
        merge(a, l, m, r, temp)
        return cnt

    def count_pairs(a, l, m, r):
        cnt = 0
        j = m + 1
        for i in range(l, m + 1):
            while j <= r and a[i] > 2 * a[j]:
                j += 1
            cnt += j - (m + 1)
        return cnt

    def merge(a, l, m, r, temp):
        i, j, k = l, m + 1, l
        while i <= m and j <= r:
            if a[i] <= a[j]:
                temp[k] = a[i]
                i += 1
            else:
                temp[k] = a[j]
                j += 1
            k += 1
        while i <= m:
            temp[k] = a[i]
            i += 1
            k += 1
        while j <= r:
            temp[k] = a[j]
            j += 1
            k += 1
        for t in range(l, r + 1):
            a[t] = temp[t]

    temp = [0] * len(nums)
    arr = list(nums)
    return sort_count(arr, 0, len(arr) - 1, temp)

if __name__ == "__main__":
    tests = [
        [1, 3, 2, 3, 1],
        [2, 4, 3, 5, 1],
        [5, 4, 3, 2, 1],
        [1, 1, 1, 1],
        [-5, -5],
    ]
    for t in tests:
        print(reverse_pairs(t))