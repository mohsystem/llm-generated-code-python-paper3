import heapq

class MedianFinder:
    def __init__(self):
        """
        initialize your data structure here.
        """
        # max-heap for the smaller half, stores negated values
        self.lower_half = []
        # min-heap for the larger half
        self.upper_half = []

    def addNum(self, num: int) -> None:
        # Python's heapq is a min-heap. To simulate a max-heap for the lower half,
        # we store negated numbers.
        
        # Add to the max-heap (lower_half)
        heapq.heappush(self.lower_half, -num)
        
        # Move the largest element from lower_half to upper_half
        heapq.heappush(self.upper_half, -heapq.heappop(self.lower_half))
        
        # Balance the heaps: lower_half should have an equal or one more element
        if len(self.upper_half) > len(self.lower_half):
            heapq.heappush(self.lower_half, -heapq.heappop(self.upper_half))

    def findMedian(self) -> float:
        # If total numbers are odd, the median is the root of the max-heap (lower_half)
        if len(self.lower_half) > len(self.upper_half):
            return float(-self.lower_half[0])
        else:
            # If total numbers are even, median is the average of the two roots
            return (-self.lower_half[0] + self.upper_half[0]) / 2.0

def main():
    # Test Case 1
    print("Test Case 1:")
    medianFinder1 = MedianFinder()
    medianFinder1.addNum(1)
    medianFinder1.addNum(2)
    print(f"Median: {medianFinder1.findMedian()}")  # Output: 1.5
    medianFinder1.addNum(3)
    print(f"Median: {medianFinder1.findMedian()}")  # Output: 2.0
    print()

    # Test Case 2
    print("Test Case 2:")
    medianFinder2 = MedianFinder()
    medianFinder2.addNum(6)
    print(f"Median: {medianFinder2.findMedian()}")  # Output: 6.0
    medianFinder2.addNum(10)
    print(f"Median: {medianFinder2.findMedian()}")  # Output: 8.0
    print()
    
    # Test Case 3
    print("Test Case 3:")
    medianFinder3 = MedianFinder()
    medianFinder3.addNum(1)
    medianFinder3.addNum(2)
    medianFinder3.addNum(3)
    print(f"Median: {medianFinder3.findMedian()}")  # Output: 2.0
    print()
    
    # Test Case 4
    print("Test Case 4:")
    medianFinder4 = MedianFinder()
    medianFinder4.addNum(-1)
    medianFinder4.addNum(-2)
    print(f"Median: {medianFinder4.findMedian()}")  # Output: -1.5
    medianFinder4.addNum(-3)
    print(f"Median: {medianFinder4.findMedian()}")  # Output: -2.0
    medianFinder4.addNum(-4)
    print(f"Median: {medianFinder4.findMedian()}")  # Output: -2.5
    print()
    
    # Test Case 5
    print("Test Case 5:")
    medianFinder5 = MedianFinder()
    medianFinder5.addNum(0)
    print(f"Median: {medianFinder5.findMedian()}")  # Output: 0.0
    print()

if __name__ == "__main__":
    main()