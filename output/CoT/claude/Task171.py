
def reversePairs(nums):
    if not nums or len(nums) < 2:
        return 0
    
    def mergeSort(left, right):
        if left >= right:
            return 0
        
        mid = left + (right - left) // 2
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
    test1 = [1, 3, 2, 3, 1]
    print("Test 1:", reversePairs(test1))  # Expected: 2
    
    # Test case 2
    test2 = [2, 4, 3, 5, 1]
    print("Test 2:", reversePairs(test2))  # Expected: 3
    
    # Test case 3
    test3 = [5, 4, 3, 2, 1]
    print("Test 3:", reversePairs(test3))  # Expected: 4
    
    # Test case 4
    test4 = [1, 2, 3, 4, 5]
    print("Test 4:", reversePairs(test4))  # Expected: 0
    
    # Test case 5
    test5 = [2147483647, 2147483647, 2147483647, 2147483647, 2147483647, 2147483647]
    print("Test 5:", reversePairs(test5))  # Expected: 0
