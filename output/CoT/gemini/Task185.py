import math

class Task185:
    def findMedianSortedArrays(self, nums1, nums2):
        # Ensure nums1 is the smaller array to optimize binary search
        if len(nums1) > len(nums2):
            return self.findMedianSortedArrays(nums2, nums1)

        m, n = len(nums1), len(nums2)
        low, high = 0, m
        
        while low <= high:
            partitionX = (low + high) // 2
            partitionY = (m + n + 1) // 2 - partitionX

            # Get the four boundary elements for the partitions
            maxX = nums1[partitionX - 1] if partitionX != 0 else -math.inf
            minX = nums1[partitionX] if partitionX != m else math.inf
            
            maxY = nums2[partitionY - 1] if partitionY != 0 else -math.inf
            minY = nums2[partitionY] if partitionY != n else math.inf

            if maxX <= minY and maxY <= minX:
                # Correct partition found, calculate the median
                if (m + n) % 2 == 0:
                    # Even number of total elements
                    return (max(maxX, maxY) + min(minX, minY)) / 2.0
                else:
                    # Odd number of total elements
                    return float(max(maxX, maxY))
            elif maxX > minY:
                # Partition in nums1 is too large, move to the left half
                high = partitionX - 1
            else:
                # Partition in nums1 is too small, move to the right half
                low = partitionX + 1
        
        # This line should not be reached if the input arrays are sorted
        raise ValueError("Input arrays are not sorted.")

if __name__ == "__main__":
    solution = Task185()

    # Test Case 1
    nums1_1 = [1, 3]
    nums2_1 = [2]
    print(f"Test Case 1: {solution.findMedianSortedArrays(nums1_1, nums2_1)}")

    # Test Case 2
    nums1_2 = [1, 2]
    nums2_2 = [3, 4]
    print(f"Test Case 2: {solution.findMedianSortedArrays(nums1_2, nums2_2)}")

    # Test Case 3
    nums1_3 = [0, 0]
    nums2_3 = [0, 0]
    print(f"Test Case 3: {solution.findMedianSortedArrays(nums1_3, nums2_3)}")

    # Test Case 4
    nums1_4 = []
    nums2_4 = [1]
    print(f"Test Case 4: {solution.findMedianSortedArrays(nums1_4, nums2_4)}")

    # Test Case 5
    nums1_5 = [2]
    nums2_5 = []
    print(f"Test Case 5: {solution.findMedianSortedArrays(nums1_5, nums2_5)}")