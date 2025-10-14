class Task170:
    def countRangeSum(self, nums: list[int], lower: int, upper: int) -> int:
        n = len(nums)
        prefix_sums = [0] * (n + 1)
        for i in range(n):
            prefix_sums[i + 1] = prefix_sums[i] + nums[i]

        def merge_sort_and_count(start, end):
            if start >= end:
                return 0
            
            mid = start + (end - start) // 2
            count = merge_sort_and_count(start, mid) + \
                    merge_sort_and_count(mid + 1, end)
            
            l, r = mid + 1, mid + 1
            for i in range(start, mid + 1):
                while l <= end and prefix_sums[l] - prefix_sums[i] < lower:
                    l += 1
                while r <= end and prefix_sums[r] - prefix_sums[i] <= upper:
                    r += 1
                count += (r - l)
                
            # Merge step
            temp = []
            p1, p2 = start, mid + 1
            while p1 <= mid and p2 <= end:
                if prefix_sums[p1] <= prefix_sums[p2]:
                    temp.append(prefix_sums[p1])
                    p1 += 1
                else:
                    temp.append(prefix_sums[p2])
                    p2 += 1
            while p1 <= mid:
                temp.append(prefix_sums[p1])
                p1 += 1
            while p2 <= end:
                temp.append(prefix_sums[p2])
                p2 += 1
            
            for i in range(len(temp)):
                prefix_sums[start + i] = temp[i]
                
            return count

        return merge_sort_and_count(0, n)

if __name__ == "__main__":
    solver = Task170()
    
    # Test Case 1
    nums1 = [-2, 5, -1]
    lower1 = -2
    upper1 = 2
    print(f"Test Case 1: {solver.countRangeSum(nums1, lower1, upper1)}")

    # Test Case 2
    nums2 = [0]
    lower2 = 0
    upper2 = 0
    print(f"Test Case 2: {solver.countRangeSum(nums2, lower2, upper2)}")

    # Test Case 3
    nums3 = [1, -1, 1, -1]
    lower3 = 0
    upper3 = 0
    print(f"Test Case 3: {solver.countRangeSum(nums3, lower3, upper3)}")

    # Test Case 4
    import sys
    nums4 = [sys.maxsize, -sys.maxsize-1, 0, -1, 1]
    lower4 = -1
    upper4 = 1
    print(f"Test Case 4: {solver.countRangeSum(nums4, lower4, upper4)}")
    
    # Test Case 5
    nums5 = [0, 0, 0, 0, 0]
    lower5 = 0
    upper5 = 0
    print(f"Test Case 5: {solver.countRangeSum(nums5, lower5, upper5)}")