import heapq
from typing import List

class MedianFinder:
    def __init__(self):
        """
        initialize your data structure here.
        """
        # lower_half is a max-heap, implemented by storing negative values in a min-heap
        self.lower_half: List[int] = []
        # upper_half is a min-heap
        self.upper_half: List[int] = []

    def addNum(self, num: int) -> None:
        # Add to max-heap (lower_half), then move the largest element to min-heap (upper_half)
        heapq.heappush(self.lower_half, -num)
        heapq.heappush(self.upper_half, -heapq.heappop(self.lower_half))
        
        # Balance the heaps if necessary: lower_half should have N or N+1 elements, upper_half N
        if len(self.lower_half) < len(self.upper_half):
            heapq.heappush(self.lower_half, -heapq.heappop(self.upper_half))

    def findMedian(self) -> float:
        # If total number of elements is odd, the median is the top of the max-heap
        if len(self.lower_half) > len(self.upper_half):
            return -self.lower_half[0]
        # If total number is even, median is the average of the two heap tops
        else:
            return (-self.lower_half[0] + self.upper_half[0]) / 2.0

def main():
    # Test Case 1: Example from prompt
    print("Test Case 1:")
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(f"Median: {mf1.findMedian():.5f}") # Expected: 1.50000
    mf1.addNum(3)
    print(f"Median: {mf1.findMedian():.5f}") # Expected: 2.00000
    print()

    # Test Case 2: Negative numbers
    print("Test Case 2:")
    mf2 = MedianFinder()
    mf2.addNum(-1)
    print(f"Median: {mf2.findMedian():.5f}") # Expected: -1.00000
    mf2.addNum(-2)
    print(f"Median: {mf2.findMedian():.5f}") # Expected: -1.50000
    mf2.addNum(-3)
    print(f"Median: {mf2.findMedian():.5f}") # Expected: -2.00000
    print()

    # Test Case 3: Zeros
    print("Test Case 3:")
    mf3 = MedianFinder()
    mf3.addNum(0)
    mf3.addNum(0)
    print(f"Median: {mf3.findMedian():.5f}") # Expected: 0.00000
    mf3.addNum(0)
    print(f"Median: {mf3.findMedian():.5f}") # Expected: 0.00000
    print()

    # Test Case 4: Mixed numbers
    print("Test Case 4:")
    mf4 = MedianFinder()
    mf4.addNum(6)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 6.00000
    mf4.addNum(10)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 8.00000
    mf4.addNum(2)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 6.00000
    mf4.addNum(6)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 6.00000
    mf4.addNum(5)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 6.00000
    mf4.addNum(0)
    print(f"Median: {mf4.findMedian():.5f}") # Expected: 5.50000
    print()

    # Test Case 5: Descending order
    print("Test Case 5:")
    mf5 = MedianFinder()
    mf5.addNum(10)
    mf5.addNum(9)
    mf5.addNum(8)
    mf5.addNum(7)
    mf5.addNum(6)
    print(f"Median: {mf5.findMedian():.5f}") # Expected: 8.00000
    mf5.addNum(5)
    print(f"Median: {mf5.findMedian():.5f}") # Expected: 7.50000
    print()

if __name__ == "__main__":
    main()