
from typing import List

def reversePairs(nums: List[int]) -> int:
    if not nums or len(nums) < 2:
        return 0
    
    n = len(nums)
    if n > 50000:
        return 0
    
    temp = [0] * n
    return merge_sort(nums, temp, 0, n - 1)

def merge_sort(nums: List[int], temp: List[int], left: int, right: int) -> int:
    if left >= right:
        return 0
    
    mid = left + (right - left) // 2
    count = merge_sort(nums, temp, left, mid) + merge_sort(nums, temp, mid + 1, right)
    
    j = mid + 1
    for i in range(left, mid + 1):
        while j <= right and nums[i] > 2 * nums[j]:
            j += 1
        count += j - (mid + 1)
    
    merge(nums, temp, left, mid, right)
    return count

def merge(nums: List[int], temp: List[int], left: int, mid: int, right: int) -> None:
    for i in range(left, right + 1):
        temp[i] = nums[i]
    
    i = left
    j = mid + 1
    k = left
    
    while i <= mid and j <= right:
        if temp[i] <= temp[j]:
            nums[k] = temp[i]
            i += 1
        else:
            nums[k] = temp[j]
            j += 1
        k += 1
    
    while i <= mid:
        nums[k] = temp[i]
        i += 1
        k += 1
    
    while j <= right:
        nums[k] = temp[j]
        j += 1
        k += 1

if __name__ == "__main__":
    test_cases = [
        [1, 3, 2, 3, 1],
        [2, 4, 3, 5, 1],
        [5, 4, 3, 2, 1],
        [1, 2, 3, 4, 5],
        [-5, -2, -1, -3, -4]
    ]
    
    expected = [2, 3, 4, 0, 1]
    
    for i, nums in enumerate(test_cases):
        nums_copy = nums.copy()
        result = reversePairs(nums_copy)
        print(f"Test {i + 1}: {result} (Expected: {expected[i]})")
