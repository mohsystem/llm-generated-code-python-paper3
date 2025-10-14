
from typing import List

def count_range_sum(nums: List[int], lower: int, upper: int) -> int:
    if not nums:
        return 0
    
    n = len(nums)
    prefix_sum = [0] * (n + 1)
    
    for i in range(n):
        prefix_sum[i + 1] = prefix_sum[i] + nums[i]
    
    def merge_sort(sums: List[int], start: int, end: int) -> int:
        if end - start <= 1:
            return 0
        
        mid = start + (end - start) // 2
        count = merge_sort(sums, start, mid) + merge_sort(sums, mid, end)
        
        j = k = t = mid
        cache = []
        
        for i in range(start, mid):
            while k < end and sums[k] - sums[i] < lower:
                k += 1
            while j < end and sums[j] - sums[i] <= upper:
                j += 1
            while t < end and sums[t] < sums[i]:
                cache.append(sums[t])
                t += 1
            cache.append(sums[i])
            count += j - k
        
        sums[start:start + len(cache)] = cache
        return count
    
    return merge_sort(prefix_sum, 0, n + 1)

def main():
    test_cases = [
        ([-2, 5, -1], -2, 2),
        ([0], 0, 0),
        ([-3, 1, 2, -2, 2, -1], -3, 3),
        ([5], 4, 6),
        ([2147483647, -2147483648, -1, 0], -10, 10)
    ]
    
    for i, (nums, lower, upper) in enumerate(test_cases, 1):
        result = count_range_sum(nums, lower, upper)
        print(f"Test {i}: {result}")

if __name__ == "__main__":
    main()
