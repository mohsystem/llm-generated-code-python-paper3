from typing import List

def count_range_sum(nums: List[int], lower: int, upper: int) -> int:
    n = len(nums)
    prefix_sums = [0] * (n + 1)
    for i in range(n):
        prefix_sums[i + 1] = prefix_sums[i] + nums[i]

    def merge_sort_and_count(sums: List[int], start: int, end: int) -> int:
        if end - start <= 1:
            return 0
        
        mid = start + (end - start) // 2
        count = merge_sort_and_count(sums, start, mid) + \
                merge_sort_and_count(sums, mid, end)
        
        l, r = mid, mid
        for i in range(start, mid):
            while l < end and sums[l] - sums[i] < lower:
                l += 1
            while r < end and sums[r] - sums[i] <= upper:
                r += 1
            count += r - l
        
        temp = []
        i, j = start, mid
        while i < mid and j < end:
            if sums[i] <= sums[j]:
                temp.append(sums[i])
                i += 1
            else:
                temp.append(sums[j])
                j += 1
        
        while i < mid:
            temp.append(sums[i])
            i += 1
        
        while j < end:
            temp.append(sums[j])
            j += 1
        
        for k in range(len(temp)):
            sums[start + k] = temp[k]
            
        return count

    return merge_sort_and_count(prefix_sums, 0, n + 1)

if __name__ == '__main__':
    # Test case 1
    nums1 = [-2, 5, -1]
    lower1, upper1 = -2, 2
    print(f"Test 1: {count_range_sum(nums1, lower1, upper1)}")

    # Test case 2
    nums2 = [0]
    lower2, upper2 = 0, 0
    print(f"Test 2: {count_range_sum(nums2, lower2, upper2)}")

    # Test case 3
    nums3 = [2147483647, -2147483648, -1, 0]
    lower3, upper3 = -1, 0
    print(f"Test 3: {count_range_sum(nums3, lower3, upper3)}")

    # Test case 4
    nums4 = [0, 0, 0]
    lower4, upper4 = 0, 0
    print(f"Test 4: {count_range_sum(nums4, lower4, upper4)}")

    # Test case 5
    nums5 = [-1, 1]
    lower5, upper5 = 0, 0
    print(f"Test 5: {count_range_sum(nums5, lower5, upper5)}")