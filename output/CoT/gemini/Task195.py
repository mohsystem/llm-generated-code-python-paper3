import heapq

class MedianFinder:

    def __init__(self):
        """
        initialize your data structure here.
        """
        # smallHalf is a max-heap, implemented by storing negative values in a min-heap
        self.smallHalf = []
        # largeHalf is a min-heap
        self.largeHalf = []

    def addNum(self, num: int) -> None:
        # Add to max-heap (negating the value)
        heapq.heappush(self.smallHalf, -num)
        
        # Move the largest element from smallHalf to largeHalf
        # This ensures every number in smallHalf is less than or equal to every number in largeHalf
        heapq.heappush(self.largeHalf, -heapq.heappop(self.smallHalf))
        
        # Balance the sizes if necessary
        # We want smallHalf to be either equal to or one larger than largeHalf
        if len(self.largeHalf) > len(self.smallHalf):
            heapq.heappush(self.smallHalf, -heapq.heappop(self.largeHalf))

    def findMedian(self) -> float:
        # If total number of elements is odd, the median is the root of the larger heap (smallHalf)
        if len(self.smallHalf) > len(self.largeHalf):
            return -self.smallHalf[0]
        else:
            # If total is even, median is the average of the two roots
            return (-self.smallHalf[0] + self.largeHalf[0]) / 2.0

def main():
    # Test Case 1: Example from prompt
    print("Test Case 1:")
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(f"Median: {mf1.findMedian()}") # Output: 1.5
    mf1.addNum(3)
    print(f"Median: {mf1.findMedian()}") # Output: 2.0
    print()

    # Test Case 2: Negative numbers
    print("Test Case 2:")
    mf2 = MedianFinder()
    mf2.addNum(-1)
    mf2.addNum(-2)
    print(f"Median: {mf2.findMedian()}") # Output: -1.5
    mf2.addNum(-3)
    print(f"Median: {mf2.findMedian()}") # Output: -2.0
    print()

    # Test Case 3: Mixed numbers and duplicates
    print("Test Case 3:")
    mf3 = MedianFinder()
    mf3.addNum(6)
    print(f"Median: {mf3.findMedian()}") # Output: 6.0
    mf3.addNum(10)
    print(f"Median: {mf3.findMedian()}") # Output: 8.0
    mf3.addNum(2)
    print(f"Median: {mf3.findMedian()}") # Output: 6.0
    mf3.addNum(6)
    print(f"Median: {mf3.findMedian()}") # Output: 6.0
    print()

    # Test Case 4: Zeros
    print("Test Case 4:")
    mf4 = MedianFinder()
    mf4.addNum(0)
    print(f"Median: {mf4.findMedian()}") # Output: 0.0
    mf4.addNum(0)
    print(f"Median: {mf4.findMedian()}") # Output: 0.0
    print()

    # Test Case 5: Descending order
    print("Test Case 5:")
    mf5 = MedianFinder()
    mf5.addNum(5)
    mf5.addNum(4)
    mf5.addNum(3)
    mf5.addNum(2)
    mf5.addNum(1)
    print(f"Median: {mf5.findMedian()}") # Output: 3.0

if __name__ == "__main__":
    main()