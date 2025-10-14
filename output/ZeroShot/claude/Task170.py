
def count_range_sum(nums, lower, upper):
    n = len(nums)
    prefix_sum = [0] * (n + 1)
    
    # Build prefix sum array
    for i in range(n):
        prefix_sum[i + 1] = prefix_sum[i] + nums[i]
    
    def count_while_merge_sort(sums, start, end):
        if end - start <= 1:
            return 0
        
        mid = (start + end) // 2
        count = count_while_merge_sort(sums, start, mid) + count_while_merge_sort(sums, mid, end)
        
        j = k = t = mid
        cache = []
        
        for i in range(start, mid):
            # Count ranges [i, j) where sum is in [lower, upper]
            while k < end and sums[k] - sums[i] < lower:
                k += 1
            while j < end and sums[j] - sums[i] <= upper:
                j += 1
            count += j - k
            
            # Merge sort
            while t < end and sums[t] < sums[i]:
                cache.append(sums[t])
                t += 1
            cache.append(sums[i])
        
        sums[start:start + len(cache)] = cache
        
        return count
    
    return count_while_merge_sort(prefix_sum, 0, n + 1)

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", count_range_sum([-2, 5, -1], -2, 2))  # Expected: 3
    
    # Test case 2
    print("Test 2:", count_range_sum([0], 0, 0))  # Expected: 1
    
    # Test case 3
    print("Test 3:", count_range_sum([-2, 5, -1, 3, -2], -2, 3))  # Expected: 8
    
    # Test case 4
    print("Test 4:", count_range_sum([1, 2, 3, 4, 5], 3, 7))  # Expected: 6
    
    # Test case 5
    print("Test 5:", count_range_sum([-1, -2, -3], -5, -1))  # Expected: 5
