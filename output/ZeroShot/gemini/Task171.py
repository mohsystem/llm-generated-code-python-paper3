class Task171:
    def reversePairs(self, nums: list[int]) -> int:
        if not nums or len(nums) < 2:
            return 0
        return self._mergeSortAndCount(nums, 0, len(nums) - 1)

    def _mergeSortAndCount(self, nums: list[int], start: int, end: int) -> int:
        if start >= end:
            return 0

        mid = start + (end - start) // 2
        count = self._mergeSortAndCount(nums, start, mid)
        count += self._mergeSortAndCount(nums, mid + 1, end)

        # Count reverse pairs
        j = mid + 1
        for i in range(start, mid + 1):
            while j <= end and nums[i] > 2 * nums[j]:
                j += 1
            count += j - (mid + 1)
        
        # Merge the two sorted halves
        temp = []
        i, j = start, mid + 1
        while i <= mid and j <= end:
            if nums[i] <= nums[j]:
                temp.append(nums[i])
                i += 1
            else:
                temp.append(nums[j])
                j += 1
        
        while i <= mid:
            temp.append(nums[i])
            i += 1
        
        while j <= end:
            temp.append(nums[j])
            j += 1
        
        for k in range(len(temp)):
            nums[start + k] = temp[k]
            
        return count

def main():
    solver = Task171()
    
    # Test Case 1
    nums1 = [1, 3, 2, 3, 1]
    print(f"Test Case 1: {solver.reversePairs(nums1[:])}")

    # Test Case 2
    nums2 = [2, 4, 3, 5, 1]
    print(f"Test Case 2: {solver.reversePairs(nums2[:])}")

    # Test Case 3
    nums3 = [2147483647, 2147483647, 2147483647, 2147483647, 2147483647]
    print(f"Test Case 3: {solver.reversePairs(nums3[:])}")

    # Test Case 4
    nums4 = [-5, -5]
    print(f"Test Case 4: {solver.reversePairs(nums4[:])}")
    
    # Test Case 5
    nums5 = []
    print(f"Test Case 5: {solver.reversePairs(nums5[:])}")

if __name__ == "__main__":
    main()