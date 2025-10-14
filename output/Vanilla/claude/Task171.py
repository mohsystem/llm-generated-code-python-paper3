
def reversePairs(nums):
    if not nums:
        return 0
    
    def mergeSort(left, right):
        if left >= right:
            return 0
        
        mid = (left + right) // 2
        count = mergeSort(left, mid) + mergeSort(mid + 1, right)
        
        # Count reverse pairs
        j = mid + 1
        for i in range(left, mid + 1):
            while j <= right and nums[i] > 2 * nums[j]:
                j += 1
            count += j - (mid + 1)
        
        # Merge
        temp = []
        i, j = left, mid + 1
        while i <= mid and j <= right:
            if nums[i] <= nums[j]:
                temp.append(nums[i])
                i += 1
            else:
                temp.append(nums[j])
                j += 1
        
        while i <= mid:
            temp.append(nums[i])
            i += 1
        
        while j <= right:
            temp.append(nums[j])
            j += 1
        
        for i in range(len(temp)):
            nums[left + i] = temp[i]
        
        return count
    
    return mergeSort(0, len(nums) - 1)


if __name__ == "__main__":
    # Test case 1
    nums1 = [1, 3, 2, 3, 1]
    print(f"Test 1: {reversePairs(nums1)}")  # Expected: 2
    
    # Test case 2
    nums2 = [2, 4, 3, 5, 1]
    print(f"Test 2: {reversePairs(nums2)}")  # Expected: 3
    
    # Test case 3
    nums3 = [5, 4, 3, 2, 1]
    print(f"Test 3: {reversePairs(nums3)}")  # Expected: 4
    
    # Test case 4
    nums4 = [1, 2, 3, 4, 5]
    print(f"Test 4: {reversePairs(nums4)}")  # Expected: 0
    
    # Test case 5
    nums5 = [2147483647, 2147483647, 2147483647, 2147483647, 2147483647, 2147483647]
    print(f"Test 5: {reversePairs(nums5)}")  # Expected: 0
