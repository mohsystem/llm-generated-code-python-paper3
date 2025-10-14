
import heapq

class MedianFinder:
    def __init__(self):
        # max heap (inverted min heap) for smaller half
        self.max_heap = []
        # min heap for larger half
        self.min_heap = []
    
    def addNum(self, num: int) -> None:
        # Validate input is within constraints
        if num < -100000 or num > 100000:
            raise ValueError("Number out of valid range")
        
        # Add to max heap (negate for max heap behavior)
        heapq.heappush(self.max_heap, -num)
        
        # Balance: move largest from max_heap to min_heap
        if self.max_heap:
            heapq.heappush(self.min_heap, -heapq.heappop(self.max_heap))
        
        # Rebalance if min_heap has more elements
        if len(self.min_heap) > len(self.max_heap):
            heapq.heappush(self.max_heap, -heapq.heappop(self.min_heap))
    
    def findMedian(self) -> float:
        # Ensure data structure is not empty
        if not self.max_heap and not self.min_heap:
            raise ValueError("No elements in data structure")
        
        if len(self.max_heap) > len(self.min_heap):
            return -self.max_heap[0]
        else:
            return (-self.max_heap[0] + self.min_heap[0]) / 2.0

def main():
    # Test case 1: Example from problem
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print("Test 1:", mf1.findMedian())  # Expected: 1.5
    mf1.addNum(3)
    print("Test 1:", mf1.findMedian())  # Expected: 2.0
    
    # Test case 2: Single element
    mf2 = MedianFinder()
    mf2.addNum(5)
    print("Test 2:", mf2.findMedian())  # Expected: 5.0
    
    # Test case 3: Negative numbers
    mf3 = MedianFinder()
    mf3.addNum(-1)
    mf3.addNum(-2)
    mf3.addNum(-3)
    print("Test 3:", mf3.findMedian())  # Expected: -2.0
    
    # Test case 4: Mixed positive and negative
    mf4 = MedianFinder()
    mf4.addNum(-5)
    mf4.addNum(10)
    print("Test 4:", mf4.findMedian())  # Expected: 2.5
    
    # Test case 5: Large sequence
    mf5 = MedianFinder()
    mf5.addNum(12)
    mf5.addNum(10)
    mf5.addNum(13)
    mf5.addNum(11)
    mf5.addNum(5)
    mf5.addNum(15)
    print("Test 5:", mf5.findMedian())  # Expected: 11.5

if __name__ == "__main__":
    main()
