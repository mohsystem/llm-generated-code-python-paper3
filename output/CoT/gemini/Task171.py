class Task171:
    def reversePairs(self, nums: list[int]) -> int:
        if not nums or len(nums) < 2:
            return 0
        
        def merge_sort(arr, low, high):
            if low >= high:
                return 0
            
            mid = low + (high - low) // 2
            count = merge_sort(arr, low, mid)
            count += merge_sort(arr, mid + 1, high)
            
            # Count reverse pairs
            j = mid + 1
            for i in range(low, mid + 1):
                while j <= high and arr[i] > 2 * arr[j]:
                    j += 1
                count += j - (mid + 1)
            
            # Merge step
            arr[low:high+1] = sorted(arr[low:high+1])
            return count

        return merge_sort(nums, 0, len(nums) - 1)

if __name__ == '__main__':
    solution = Task171()

    # Test Case 1
    nums1 = [1, 3, 2, 3, 1]
    print(f"Test Case 1: {solution.reversePairs(nums1)}") # Expected: 2

    # Test Case 2
    nums2 = [2, 4, 3, 5, 1]
    print(f"Test Case 2: {solution.reversePairs(nums2)}") # Expected: 3

    # Test Case 3
    nums3 = [5, 4, 3, 2, 1]
    print(f"Test Case 3: {solution.reversePairs(nums3)}") # Expected: 4

    # Test Case 4
    nums4 = [2147483647, 1000000000]
    print(f"Test Case 4: {solution.reversePairs(nums4)}") # Expected: 1

    # Test Case 5
    nums5 = [-1, -2, -3]
    print(f"Test Case 5: {solution.reversePairs(nums5)}") # Expected: 3