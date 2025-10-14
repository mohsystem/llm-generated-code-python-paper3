import collections

class Task171:
    def reversePairs(self, nums: list[int]) -> int:
        if not nums:
            return 0
        return self._mergeSort(nums, 0, len(nums) - 1)

    def _mergeSort(self, nums: list[int], left: int, right: int) -> int:
        if left >= right:
            return 0

        mid = left + (right - left) // 2
        count = self._mergeSort(nums, left, mid)
        count += self._mergeSort(nums, mid + 1, right)
        count += self._mergeAndCount(nums, left, mid, right)
        return count

    def _mergeAndCount(self, nums: list[int], left: int, mid: int, right: int) -> int:
        count = 0
        j = mid + 1
        for i in range(left, mid + 1):
            while j <= right and nums[i] > 2 * nums[j]:
                j += 1
            count += (j - (mid + 1))
        
        # Standard merge step
        temp = []
        i, k = left, mid + 1
        while i <= mid and k <= right:
            if nums[i] <= nums[k]:
                temp.append(nums[i])
                i += 1
            else:
                temp.append(nums[k])
                k += 1
        
        while i <= mid:
            temp.append(nums[i])
            i += 1
        
        while k <= right:
            temp.append(nums[k])
            k += 1
            
        for l in range(len(temp)):
            nums[left + l] = temp[l]
            
        return count

if __name__ == "__main__":
    solution = Task171()

    # Test Case 1
    nums1 = [1, 3, 2, 3, 1]
    print(f"Test Case 1: {solution.reversePairs(list(nums1))}")

    # Test Case 2
    nums2 = [2, 4, 3, 5, 1]
    print(f"Test Case 2: {solution.reversePairs(list(nums2))}")
    
    # Test Case 3
    nums3 = []
    print(f"Test Case 3: {solution.reversePairs(list(nums3))}")
    
    # Test Case 4
    nums4 = [5, 4, 3, 2, 1]
    print(f"Test Case 4: {solution.reversePairs(list(nums4))}")
    
    # Test Case 5
    nums5 = [2147483647, 2147483647, 2147483647, 2147483647, 2147483647, 2147483647]
    print(f"Test Case 5: {solution.reversePairs(list(nums5))}")