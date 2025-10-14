
import heapq

class MedianFinder:
    def __init__(self):
        self.max_heap = []  # left half (max heap, using negative values)
        self.min_heap = []  # right half (min heap)

    def addNum(self, num: int) -> None:
        if not self.max_heap or num <= -self.max_heap[0]:
            heapq.heappush(self.max_heap, -num)
        else:
            heapq.heappush(self.min_heap, num)
        
        # Balance the heaps
        if len(self.max_heap) > len(self.min_heap) + 1:
            heapq.heappush(self.min_heap, -heapq.heappop(self.max_heap))
        elif len(self.min_heap) > len(self.max_heap):
            heapq.heappush(self.max_heap, -heapq.heappop(self.min_heap))

    def findMedian(self) -> float:
        if len(self.max_heap) == len(self.min_heap):
            return (-self.max_heap[0] + self.min_heap[0]) / 2.0
        else:
            return -self.max_heap[0]


if __name__ == "__main__":
    # Test case 1
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print("Test 1:", mf1.findMedian())  # 1.5
    mf1.addNum(3)
    print("Test 1:", mf1.findMedian())  # 2.0

    # Test case 2
    mf2 = MedianFinder()
    mf2.addNum(5)
    print("Test 2:", mf2.findMedian())  # 5.0

    # Test case 3
    mf3 = MedianFinder()
    mf3.addNum(10)
    mf3.addNum(20)
    mf3.addNum(30)
    mf3.addNum(40)
    print("Test 3:", mf3.findMedian())  # 25.0

    # Test case 4
    mf4 = MedianFinder()
    mf4.addNum(-1)
    mf4.addNum(-2)
    mf4.addNum(-3)
    print("Test 4:", mf4.findMedian())  # -2.0

    # Test case 5
    mf5 = MedianFinder()
    mf5.addNum(6)
    mf5.addNum(10)
    mf5.addNum(2)
    mf5.addNum(6)
    mf5.addNum(5)
    print("Test 5:", mf5.findMedian())  # 6.0
