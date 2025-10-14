import heapq

class MedianFinder:
    def __init__(self):
        """
        initialize your data structure here.
        """
        # Two heaps: small_half (max heap), large_half (min heap)
        # small_half is one element larger or of the same size as large_half
        self.small_half = []  # max heap, stores negative values to simulate
        self.large_half = []  # min heap

    def addNum(self, num: int) -> None:
        # Push to max heap (small_half)
        heapq.heappush(self.small_half, -1 * num)
        
        # Move the largest element from small_half to large_half to maintain order
        heapq.heappush(self.large_half, -1 * heapq.heappop(self.small_half))
        
        # Balance the heaps if large_half becomes larger
        if len(self.small_half) < len(self.large_half):
            heapq.heappush(self.small_half, -1 * heapq.heappop(self.large_half))

    def findMedian(self) -> float:
        # If total numbers are odd, median is in the max_heap
        if len(self.small_half) > len(self.large_half):
            return -1 * self.small_half[0]
        # If total numbers are even, median is avg of tops of both heaps
        else:
            return (-1 * self.small_half[0] + self.large_half[0]) / 2.0

# The main class is not named Task195 as Python does not have the same
# strict "main class" concept as Java. The testing logic is in the main execution block.
if __name__ == "__main__":
    # Test Case 1: Example from description
    print("Test Case 1:")
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(f"Median: {mf1.findMedian()}") # Expected: 1.5
    mf1.addNum(3)
    print(f"Median: {mf1.findMedian()}") # Expected: 2.0
    print()

    # Test Case 2: Negative numbers
    print("Test Case 2:")
    mf2 = MedianFinder()
    mf2.addNum(-1)
    print(f"Median: {mf2.findMedian()}") # Expected: -1.0
    mf2.addNum(-2)
    print(f"Median: {mf2.findMedian()}") # Expected: -1.5
    mf2.addNum(-3)
    print(f"Median: {mf2.findMedian()}") # Expected: -2.0
    print()
    
    # Test Case 3: Zero
    print("Test Case 3:")
    mf3 = MedianFinder()
    mf3.addNum(0)
    print(f"Median: {mf3.findMedian()}") # Expected: 0.0
    mf3.addNum(0)
    print(f"Median: {mf3.findMedian()}") # Expected: 0.0
    print()

    # Test Case 4: Alternating large and small numbers
    print("Test Case 4:")
    mf4 = MedianFinder()
    mf4.addNum(10)
    mf4.addNum(1)
    mf4.addNum(100)
    mf4.addNum(5)
    # Nums: [1, 5, 10, 100], Median: (5+10)/2 = 7.5
    print(f"Median: {mf4.findMedian()}")
    print()

    # Test Case 5: Descending order
    print("Test Case 5:")
    mf5 = MedianFinder()
    mf5.addNum(5)
    mf5.addNum(4)
    mf5.addNum(3)
    mf5.addNum(2)
    mf5.addNum(1)
    # Nums: [1, 2, 3, 4, 5], Median: 3
    print(f"Median: {mf5.findMedian()}")
    print()