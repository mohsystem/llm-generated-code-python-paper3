
from typing import List

def count_smaller(nums: List[int]) -> List[int]:
    if not nums:
        return []
    
    # Validate input constraints
    if len(nums) > 100000:
        raise ValueError("Array length exceeds maximum allowed size")
    
    for num in nums:
        if not isinstance(num, int) or num < -10000 or num > 10000:
            raise ValueError("Array element out of valid range")
    
    n = len(nums)
    counts = [0] * n
    indices = list(range(n))
    
    def merge_sort(left: int, right: int) -> None:
        if left >= right:
            return
        
        mid = left + (right - left) // 2
        merge_sort(left, mid)
        merge_sort(mid + 1, right)
        merge(left, mid, right)
    
    def merge(left: int, mid: int, right: int) -> None:
        temp = []
        i, j = left, mid + 1
        right_count = 0
        
        while i <= mid and j <= right:
            if nums[indices[j]] < nums[indices[i]]:
                temp.append(indices[j])
                j += 1
                right_count += 1
            else:
                counts[indices[i]] += right_count
                temp.append(indices[i])
                i += 1
        
        while i <= mid:
            counts[indices[i]] += right_count
            temp.append(indices[i])
            i += 1
        
        while j <= right:
            temp.append(indices[j])
            j += 1
        
        for idx, val in enumerate(temp):
            indices[left + idx] = val
    
    merge_sort(0, n - 1)
    return counts

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", count_smaller([5, 2, 6, 1]))
    
    # Test case 2
    print("Test 2:", count_smaller([-1]))
    
    # Test case 3
    print("Test 3:", count_smaller([-1, -1]))
    
    # Test case 4
    print("Test 4:", count_smaller([1, 2, 3, 4, 5]))
    
    # Test case 5
    print("Test 5:", count_smaller([5, 4, 3, 2, 1]))
