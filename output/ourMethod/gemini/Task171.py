from typing import List

def reversePairs(nums: List[int]) -> int:
    """
    Calculates the number of reverse pairs in an array.
    A reverse pair is (i, j) where i < j and nums[i] > 2 * nums[j].
    """
    
    def merge_sort(low: int, high: int) -> int:
        if low >= high:
            return 0
        
        mid = low + (high - low) // 2
        count = merge_sort(low, mid)
        count += merge_sort(mid + 1, high)
        
        # Count reverse pairs
        j = mid + 1
        for i in range(low, mid + 1):
            while j <= high and nums[i] > 2 * nums[j]:
                j += 1
            count += (j - (mid + 1))
        
        # Merge step
        temp = []
        i, k = low, mid + 1
        while i <= mid and k <= high:
            if nums[i] <= nums[k]:
                temp.append(nums[i])
                i += 1
            else:
                temp.append(nums[k])
                k += 1
        while i <= mid:
            temp.append(nums[i])
            i += 1
        while k <= high:
            temp.append(nums[k])
            k += 1
        
        for idx in range(len(temp)):
            nums[low + idx] = temp[idx]
            
        return count

    if not nums:
        return 0
    return merge_sort(0, len(nums) - 1)

if __name__ == '__main__':
    # Test case 1
    nums1 = [1, 3, 2, 3, 1]
    print(f"Test Case 1: {reversePairs(nums1)}")

    # Test case 2
    nums2 = [2, 4, 3, 5, 1]
    print(f"Test Case 2: {reversePairs(nums2)}")

    # Test case 3
    nums3 = [2147483647, 2147483647, 2147483647, 2147483647, 2147483647, 2147483647]
    print(f"Test Case 3: {reversePairs(nums3)}")
    
    # Test case 4
    nums4 = []
    print(f"Test Case 4: {reversePairs(nums4)}")
    
    # Test case 5
    nums5 = [5, 4, 3, 2, 1]
    print(f"Test Case 5: {reversePairs(nums5)}")