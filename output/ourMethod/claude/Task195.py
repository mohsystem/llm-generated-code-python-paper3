
import heapq
from typing import List

class MedianFinder:
    def __init__(self):
        self.max_heap: List[int] = []  # left half (inverted for max heap)
        self.min_heap: List[int] = []  # right half
    
    def addNum(self, num: int) -> None:
        # Validate input is within constraints
        if num < -100000 or num > 100000:
            raise ValueError("Number out of valid range")
        
        # Add to max heap (negate for max heap behavior)
        heapq.heappush(self.max_heap, -num)
        
        # Balance: move largest from max_heap to min_heap
        if self.max_heap and self.min_heap and -self.max_heap[0] > self.min_heap[0]:
            heapq.heappush(self.min_heap, -heapq.heappop(self.max_heap))
        
        # Maintain size property
        if len(self.max_heap) > len(self.min_heap) + 1:
            heapq.heappush(self.min_heap, -heapq.heappop(self.max_heap))
        elif len(self.min_heap) > len(self.max_heap):
            heapq.heappush(self.max_heap, -heapq.heappop(self.min_heap))
    
    def findMedian(self) -> float:
        if not self.max_heap:
            raise RuntimeError("No elements in data structure")
        
        if len(self.max_heap) == len(self.min_heap):
            return (-self.max_heap[0] + self.min_heap[0]) / 2.0
        else:
            return float(-self.max_heap[0])

def main():
    # Test case 1
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(f"Test 1 - Median after [1,2]: {mf1.findMedian()}")
    mf1.addNum(3)
    print(f"Test 1 - Median after [1,2,3]: {mf1.findMedian()}")
    
    # Test case 2
    mf2 = MedianFinder()
    mf2.addNum(5)
    print(f"Test 2 - Median of [5]: {mf2.findMedian()}")
    
    # Test case 3
    mf3 = MedianFinder()
    mf3.addNum(-1)
    mf3.addNum(-2)
    mf3.addNum(-3)
    print(f"Test 3 - Median of [-1,-2,-3]: {mf3.findMedian()}")
    
    # Test case 4
    mf4 = MedianFinder()
    mf4.addNum(-5)
    mf4.addNum(10)
    mf4.addNum(3)
    mf4.addNum(-2)
    print(f"Test 4 - Median of [-5,10,3,-2]: {mf4.findMedian()}")
    
    # Test case 5
    mf5 = MedianFinder()
    for i in range(1, 11):
        mf5.addNum(i)
    print(f"Test 5 - Median of [1..10]: {mf5.findMedian()}")

if __name__ == "__main__":
    main()
