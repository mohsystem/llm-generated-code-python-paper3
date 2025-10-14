from typing import List

class Solution:
    def countSmaller(self, nums: List[int]) -> List[int]:
        n = len(nums)
        if n == 0:
            return []

        self.counts = [0] * n
        items = [(nums[i], i) for i in range(n)]

        self.merge_sort(items, 0, n - 1)

        return self.counts

    def merge_sort(self, items: List[tuple[int, int]], start: int, end: int):
        if start >= end:
            return

        mid = start + (end - start) // 2
        self.merge_sort(items, start, mid)
        self.merge_sort(items, mid + 1, end)
        self.merge(items, start, mid, end)

    def merge(self, items: List[tuple[int, int]], start: int, mid: int, end: int):
        temp = []
        i, j = start, mid + 1

        while i <= mid and j <= end:
            if items[i][0] <= items[j][0]:
                self.counts[items[i][1]] += j - (mid + 1)
                temp.append(items[i])
                i += 1
            else:
                temp.append(items[j])
                j += 1

        while i <= mid:
            self.counts[items[i][1]] += j - (mid + 1)
            temp.append(items[i])
            i += 1

        while j <= end:
            temp.append(items[j])
            j += 1

        for k in range(len(temp)):
            items[start + k] = temp[k]

if __name__ == '__main__':
    solution = Solution()
    
    # Test Case 1
    nums1 = [5, 2, 6, 1]
    print("Test Case 1:")
    print(f"Input: {nums1}")
    print(f"Output: {solution.countSmaller(nums1)}") # Expected: [2, 1, 1, 0]

    # Test Case 2
    nums2 = [-1]
    print("\nTest Case 2:")
    print(f"Input: {nums2}")
    print(f"Output: {solution.countSmaller(nums2)}") # Expected: [0]

    # Test Case 3
    nums3 = [-1, -1]
    print("\nTest Case 3:")
    print(f"Input: {nums3}")
    print(f"Output: {solution.countSmaller(nums3)}") # Expected: [0, 0]

    # Test Case 4
    nums4 = []
    print("\nTest Case 4:")
    print(f"Input: {nums4}")
    print(f"Output: {solution.countSmaller(nums4)}") # Expected: []

    # Test Case 5
    nums5 = [2, 0, 1]
    print("\nTest Case 5:")
    print(f"Input: {nums5}")
    print(f"Output: {solution.countSmaller(nums5)}") # Expected: [2, 0, 0]