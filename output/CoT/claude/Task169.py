
def countSmaller(nums):
    if not nums:
        return []
    
    n = len(nums)
    result = [0] * n
    indices = list(range(n))
    
    def merge_sort(left, right):
        if left >= right:
            return
        
        mid = (left + right) // 2
        merge_sort(left, mid)
        merge_sort(mid + 1, right)
        merge(left, mid, right)
    
    def merge(left, mid, right):
        temp = []
        i, j = left, mid + 1
        right_count = 0
        
        while i <= mid and j <= right:
            if nums[indices[j]] < nums[indices[i]]:
                temp.append(indices[j])
                j += 1
                right_count += 1
            else:
                result[indices[i]] += right_count
                temp.append(indices[i])
                i += 1
        
        while i <= mid:
            result[indices[i]] += right_count
            temp.append(indices[i])
            i += 1
        
        while j <= right:
            temp.append(indices[j])
            j += 1
        
        for i, idx in enumerate(temp):
            indices[left + i] = idx
    
    merge_sort(0, n - 1)
    return result

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", countSmaller([5, 2, 6, 1]))
    
    # Test case 2
    print("Test 2:", countSmaller([-1]))
    
    # Test case 3
    print("Test 3:", countSmaller([-1, -1]))
    
    # Test case 4
    print("Test 4:", countSmaller([1, 2, 3, 4, 5]))
    
    # Test case 5
    print("Test 5:", countSmaller([5, 4, 3, 2, 1]))
