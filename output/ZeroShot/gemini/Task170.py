from typing import List

def countRangeSum(nums: List[int], lower: int, upper: int) -> int:
    """
    Given an integer array nums and two integers lower and upper, return the number of range sums
    that lie in [lower, upper] inclusive.
    """
    if not nums:
        return 0

    n = len(nums)
    # Prefix sums can be large, but Python integers handle arbitrary size.
    prefix_sums = [0] * (n + 1)
    for i in range(n):
        prefix_sums[i + 1] = prefix_sums[i] + nums[i]

    def merge_sort_and_count(start: int, end: int) -> int:
        """
        A recursive helper function using a divide and conquer approach (Merge Sort).
        It counts the valid range sums and sorts the prefix sum subarray.
        """
        if start >= end:
            return 0
        
        mid = start + (end - start) // 2
        count = merge_sort_and_count(start, mid) + merge_sort_and_count(mid + 1, end)
        
        # Count range sums S(i, j) where i is in the left half and j in the right half.
        # For each prefix_sums[j] in the right half, we need to find how many prefix_sums[i]
        # in the left half satisfy: prefix_sums[j] - upper <= prefix_sums[i] <= prefix_sums[j] - lower
        k, l = start, start
        for j in range(mid + 1, end + 1):
            while k <= mid and prefix_sums[k] < prefix_sums[j] - upper:
                k += 1
            while l <= mid and prefix_sums[l] <= prefix_sums[j] - lower:
                l += 1
            count += l - k
            
        # Standard merge step for merge sort
        temp = []
        i, j = start, mid + 1
        while i <= mid and j <= end:
            if prefix_sums[i] <= prefix_sums[j]:
                temp.append(prefix_sums[i])
                i += 1
            else:
                temp.append(prefix_sums[j])
                j += 1
        while i <= mid:
            temp.append(prefix_sums[i])
            i += 1
        while j <= end:
            temp.append(prefix_sums[j])
            j += 1
        
        for idx in range(len(temp)):
            prefix_sums[start + idx] = temp[idx]
            
        return count

    return merge_sort_and_count(0, n)

if __name__ == '__main__':
    # Test Case 1
    nums1 = [-2, 5, -1]
    lower1, upper1 = -2, 2
    print(f"Test Case 1: {countRangeSum(nums1, lower1, upper1)}")

    # Test Case 2
    nums2 = [0]
    lower2, upper2 = 0, 0
    print(f"Test Case 2: {countRangeSum(nums2, lower2, upper2)}")

    # Test Case 3
    nums3 = [1, 1, 1]
    lower3, upper3 = 1, 2
    print(f"Test Case 3: {countRangeSum(nums3, lower3, upper3)}")
    
    # Test Case 4
    nums4 = [-1, -1, -1]
    lower4, upper4 = -2, -1
    print(f"Test Case 4: {countRangeSum(nums4, lower4, upper4)}")

    # Test Case 5
    nums5 = [2147483647, -2147483648, -1, 0]
    lower5, upper5 = -1, 0
    print(f"Test Case 5: {countRangeSum(nums5, lower5, upper5)}")