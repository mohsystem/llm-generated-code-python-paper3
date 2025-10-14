
def countRangeSum(nums, lower, upper):
    if not nums:
        return 0
    
    n = len(nums)
    prefix_sum = [0] * (n + 1)
    
    # Calculate prefix sums
    for i in range(n):
        prefix_sum[i + 1] = prefix_sum[i] + nums[i]
    
    def merge_sort_count(sums, start, end):
        if end - start <= 1:
            return 0
        
        mid = start + (end - start) // 2
        count = merge_sort_count(sums, start, mid) + merge_sort_count(sums, mid, end)
        
        j = k = t = mid
        cache = []
        
        for i in range(start, mid):
            # Count valid ranges
            while k < end and sums[k] - sums[i] < lower:
                k += 1
            while j < end and sums[j] - sums[i] <= upper:
                j += 1
            count += j - k
            
            # Merge for sorting
            while t < end and sums[t] < sums[i]:
                cache.append(sums[t])
                t += 1
            cache.append(sums[i])
        
        sums[start:start + len(cache)] = cache
        
        return count
    
    return merge_sort_count(prefix_sum, 0, n + 1)

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", countRangeSum([-2, 5, -1], -2, 2))  # Expected: 3
    
    # Test case 2
    print("Test 2:", countRangeSum([0], 0, 0))  # Expected: 1
    
    # Test case 3
    print("Test 3:", countRangeSum([-2147483647, 0, -2147483647, 2147483647], -564, 3864))  # Expected: 3
    
    # Test case 4
    print("Test 4:", countRangeSum([1, 2, 3, 4, 5], 3, 8))  # Expected: 6
    
    # Test case 5
    print("Test 5:", countRangeSum([-1, -1, -1], -2, -1))  # Expected: 6
