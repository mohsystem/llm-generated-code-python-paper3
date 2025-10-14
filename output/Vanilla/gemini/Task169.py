class Task169:
    def countSmaller(self, nums: list[int]) -> list[int]:
        n = len(nums)
        if n == 0:
            return []
            
        items = [(nums[i], i) for i in range(n)]
        counts = [0] * n

        def merge_sort(start, end):
            if start >= end:
                return
            
            mid = start + (end - start) // 2
            merge_sort(start, mid)
            merge_sort(mid + 1, end)
            merge(start, mid, end)

        def merge(start, mid, end):
            temp = []
            i, j = start, mid + 1
            right_counter = 0

            while i <= mid and j <= end:
                if items[i][0] <= items[j][0]:
                    counts[items[i][1]] += right_counter
                    temp.append(items[i])
                    i += 1
                else:
                    right_counter += 1
                    temp.append(items[j])
                    j += 1
            
            while i <= mid:
                counts[items[i][1]] += right_counter
                temp.append(items[i])
                i += 1
            
            while j <= end:
                temp.append(items[j])
                j += 1
            
            for k in range(len(temp)):
                items[start + k] = temp[k]

        merge_sort(0, n - 1)
        return counts

solver = Task169()

# Test Case 1
nums1 = [5, 2, 6, 1]
print("Test Case 1:")
print(f"Input: {nums1}")
print(f"Output: {solver.countSmaller(nums1)}")

# Test Case 2
nums2 = [-1]
print("\nTest Case 2:")
print(f"Input: {nums2}")
print(f"Output: {solver.countSmaller(nums2)}")

# Test Case 3
nums3 = [-1, -1]
print("\nTest Case 3:")
print(f"Input: {nums3}")
print(f"Output: {solver.countSmaller(nums3)}")

# Test Case 4
nums4 = [2, 0, 1]
print("\nTest Case 4:")
print(f"Input: {nums4}")
print(f"Output: {solver.countSmaller(nums4)}")

# Test Case 5
nums5 = []
print("\nTest Case 5:")
print(f"Input: {nums5}")
print(f"Output: {solver.countSmaller(nums5)}")