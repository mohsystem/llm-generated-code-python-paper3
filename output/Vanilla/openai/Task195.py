import heapq

class MedianFinder:
    def __init__(self):
        # max-heap for lower half (store negatives), min-heap for upper half
        self.low = []   # max-heap (as negatives)
        self.high = []  # min-heap

    def addNum(self, num: int) -> None:
        if not self.low or num <= -self.low[0]:
            heapq.heappush(self.low, -num)
        else:
            heapq.heappush(self.high, num)

        # Balance heaps: len(low) >= len(high) and diff <= 1
        if len(self.low) < len(self.high):
            heapq.heappush(self.low, -heapq.heappop(self.high))
        elif len(self.low) - len(self.high) > 1:
            heapq.heappush(self.high, -heapq.heappop(self.low))

    def findMedian(self) -> float:
        if len(self.low) == len(self.high):
            return (-self.low[0] + self.high[0]) / 2.0
        return float(-self.low[0])

if __name__ == "__main__":
    # Test case 1 (Example)
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(mf1.findMedian())  # 1.5
    mf1.addNum(3)
    print(mf1.findMedian())  # 2.0

    # Test case 2
    mf2 = MedianFinder()
    for x in [2, 3, 4]:
        mf2.addNum(x)
    print(mf2.findMedian())  # 3.0

    # Test case 3
    mf3 = MedianFinder()
    for x in [2, 3]:
        mf3.addNum(x)
    print(mf3.findMedian())  # 2.5

    # Test case 4 (negatives)
    mf4 = MedianFinder()
    for x in [-1, -2, -3, -4, -5]:
        mf4.addNum(x)
    print(mf4.findMedian())  # -3.0

    # Test case 5 (dynamic)
    mf5 = MedianFinder()
    mf5.addNum(5)
    print(mf5.findMedian())  # 5.0
    mf5.addNum(15)
    print(mf5.findMedian())  # 10.0
    mf5.addNum(1)
    print(mf5.findMedian())  # 5.0
    mf5.addNum(3)
    print(mf5.findMedian())  # 4.0