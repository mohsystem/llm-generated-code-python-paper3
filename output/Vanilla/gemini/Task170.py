class Task170:
    def countRangeSum(self, nums: list[int], lower: int, upper: int) -> int:
        n = len(nums)
        prefix_sums = [0] * (n + 1)
        for i in range(n):
            prefix_sums[i + 1] = prefix_sums[i] + nums[i]

        def count_and_merge(start, end):
            if start >= end:
                return 0

            mid = start + (end - start) // 2
            count = count_and_merge(start, mid) + count_and_merge(mid + 1, end)

            k, l = start, start
            for j in range(mid + 1, end + 1):
                while k <= mid and prefix_sums[k] < prefix_sums[j] - upper:
                    k += 1
                while l <= mid and prefix_sums[l] <= prefix_sums[j] - lower:
                    l += 1
                count += l - k
            
            # Merge step using slicing and sorted (simpler but could be slightly less performant)
            # or manual merge for better performance. We'll do manual merge.
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
            
            for i in range(len(temp)):
                prefix_sums[start + i] = temp[i]

            return count

        return count_and_merge(0, n)

if __name__ == "__main__":
    solver = Task170()
    
    # Test case 1
    nums1 = [-2, 5, -1]
    lower1 = -2
    upper1 = 2
    print(f"Test Case 1: {solver.countRangeSum(nums1, lower1, upper1)}")

    # Test case 2
    nums2 = [0]
    lower2 = 0
    upper2 = 0
    print(f"Test Case 2: {solver.countRangeSum(nums2, lower2, upper2)}")

    # Test case 3
    nums3 = [2147483647, -2147483648, -1, 0]
    lower3 = -1
    upper3 = 0
    print(f"Test Case 3: {solver.countRangeSum(nums3, lower3, upper3)}")

    # Test case 4
    nums4 = [0, 0, 0]
    lower4 = 0
    upper4 = 0
    print(f"Test Case 4: {solver.countRangeSum(nums4, lower4, upper4)}")

    # Test case 5
    nums5 = [-1, 1]
    lower5 = 0
    upper5 = 0
    print(f"Test Case 5: {solver.countRangeSum(nums5, lower5, upper5)}")