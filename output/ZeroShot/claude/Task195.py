
import heapq

class Task195:
    def __init__(self):
        self.max_heap = []  # stores smaller half (negated for max heap)
        self.min_heap = []  # stores larger half
    
    def addNum(self, num):
        if not self.max_heap or num <= -self.max_heap[0]:
            heapq.heappush(self.max_heap, -num)
        else:
            heapq.heappush(self.min_heap, num)
        
        # Balance heaps
        if len(self.max_heap) > len(self.min_heap) + 1:
            heapq.heappush(self.min_heap, -heapq.heappop(self.max_heap))
        elif len(self.min_heap) > len(self.max_heap):
            heapq.heappush(self.max_heap, -heapq.heappop(self.min_heap))
    
    def findMedian(self):
        if len(self.max_heap) == len(self.min_heap):
            return (-self.max_heap[0] + self.min_heap[0]) / 2.0
        return -self.max_heap[0]


if __name__ == "__main__":
    # Test case 1
    mf1 = Task195()
    mf1.addNum(1)
    mf1.addNum(2)
    print("Test 1:", mf1.findMedian())  # 1.5
    mf1.addNum(3)
    print("Test 1:", mf1.findMedian())  # 2.0
    
    # Test case 2
    mf2 = Task195()
    mf2.addNum(5)
    print("Test 2:", mf2.findMedian())  # 5.0
    
    # Test case 3
    mf3 = Task195()
    mf3.addNum(6)
    mf3.addNum(10)
    mf3.addNum(2)
    mf3.addNum(6)
    mf3.addNum(5)
    print("Test 3:", mf3.findMedian())  # 6.0
    
    # Test case 4
    mf4 = Task195()
    mf4.addNum(-1)
    mf4.addNum(-2)
    mf4.addNum(-3)
    mf4.addNum(-4)
    print("Test 4:", mf4.findMedian())  # -2.5
    
    # Test case 5
    mf5 = Task195()
    mf5.addNum(1)
    mf5.addNum(2)
    mf5.addNum(3)
    mf5.addNum(4)
    mf5.addNum(5)
    print("Test 5:", mf5.findMedian())  # 3.0
