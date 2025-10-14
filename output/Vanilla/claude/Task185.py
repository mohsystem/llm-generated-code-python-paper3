
def findMedianSortedArrays(nums1, nums2):
    if len(nums1) > len(nums2):
        return findMedianSortedArrays(nums2, nums1)
    
    m, n = len(nums1), len(nums2)
    low, high = 0, m
    
    while low <= high:
        partitionX = (low + high) // 2
        partitionY = (m + n + 1) // 2 - partitionX
        
        maxLeftX = float('-inf') if partitionX == 0 else nums1[partitionX - 1]
        minRightX = float('inf') if partitionX == m else nums1[partitionX]
        
        maxLeftY = float('-inf') if partitionY == 0 else nums2[partitionY - 1]
        minRightY = float('inf') if partitionY == n else nums2[partitionY]
        
        if maxLeftX <= minRightY and maxLeftY <= minRightX:
            if (m + n) % 2 == 0:
                return (max(maxLeftX, maxLeftY) + min(minRightX, minRightY)) / 2.0
            else:
                return max(maxLeftX, maxLeftY)
        elif maxLeftX > minRightY:
            high = partitionX - 1
        else:
            low = partitionX + 1
    
    raise ValueError("Input arrays are not sorted")

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", findMedianSortedArrays([1, 3], [2]))
    
    # Test case 2
    print("Test 2:", findMedianSortedArrays([1, 2], [3, 4]))
    
    # Test case 3
    print("Test 3:", findMedianSortedArrays([1, 2, 3, 4, 5], [6, 7, 8, 9, 10]))
    
    # Test case 4
    print("Test 4:", findMedianSortedArrays([], [1]))
    
    # Test case 5
    print("Test 5:", findMedianSortedArrays([1, 3, 5, 7, 9], [2, 4, 6, 8, 10, 12]))
