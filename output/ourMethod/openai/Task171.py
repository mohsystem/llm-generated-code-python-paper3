from typing import List, Tuple

def reverse_pairs(nums: List[int]) -> int:
    _validate(nums)
    if len(nums) <= 1:
        return 0

    # Work on a copy to avoid mutating caller input
    arr = list(nums)
    temp = [0] * len(arr)

    def sort_and_count(left: int, right: int) -> int:
        if left >= right:
            return 0
        mid = (left + right) // 2
        cnt = sort_and_count(left, mid) + sort_and_count(mid + 1, right)

        # Count cross pairs
        j = mid + 1
        for i in range(left, mid + 1):
            while j <= right and arr[i] > 2 * arr[j]:
                j += 1
            cnt += j - (mid + 1)

        # Merge
        i, j, k = left, mid + 1, left
        while i <= mid and j <= right:
            if arr[i] <= arr[j]:
                temp[k] = arr[i]
                i += 1
            else:
                temp[k] = arr[j]
                j += 1
            k += 1
        while i <= mid:
            temp[k] = arr[i]
            i += 1
            k += 1
        while j <= right:
            temp[k] = arr[j]
            j += 1
            k += 1
        for idx in range(left, right + 1):
            arr[idx] = temp[idx]
        return cnt

    return sort_and_count(0, len(arr) - 1)

def _validate(nums: List[int]) -> None:
    if not isinstance(nums, list):
        raise ValueError("Input must be a list of integers.")
    n = len(nums)
    if n < 1 or n > 50000:
        raise ValueError("Array length must be in the range [1, 50000].")
    for v in nums:
        if not isinstance(v, int):
            raise ValueError("All elements must be integers.")
        if v < -2**31 or v > 2**31 - 1:
            raise ValueError("Elements must be within 32-bit signed integer range.")

if __name__ == "__main__":
    tests: List[Tuple[List[int], int]] = [
        ([1, 3, 2, 3, 1], 2),
        ([2, 4, 3, 5, 1], 3),
        ([-5, -5], 1),
        ([2147483647, -2147483648, 0], 2),
        ([1, 2, 3, 4, 5], 0),
    ]
    for idx, (arr, expected) in enumerate(tests, 1):
        res = reverse_pairs(arr)
        print(f"Test {idx} {arr} -> {res} (expected {expected})")