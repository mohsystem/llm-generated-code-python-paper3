import heapq

class MedianFinder:
    def __init__(self):
        # max-heap (as negatives) for lower half, min-heap for upper half
        self.lower = []  # max-heap simulated by negative values
        self.upper = []  # min-heap

    def addNum(self, num: int) -> None:
        # Push to lower (as negative for max-heap behavior)
        heapq.heappush(self.lower, -num)
        # Move the largest of lower to upper
        if self.lower:
            top = -heapq.heappop(self.lower)
            heapq.heappush(self.upper, top)
        # Ensure lower has equal or one more element than upper
        if len(self.upper) > len(self.lower):
            heapq.heappush(self.lower, -heapq.heappop(self.upper))

    def findMedian(self) -> float:
        if not self.lower:
            return 0.0  # defensive
        if len(self.lower) > len(self.upper):
            return float(-self.lower[0])
        return (-self.lower[0] + self.upper[0]) / 2.0


def _run_test1():
    mf = MedianFinder()
    mf.addNum(1)
    mf.addNum(2)
    print(mf.findMedian())  # 1.5
    mf.addNum(3)
    print(mf.findMedian())  # 2.0

def _run_test2():
    mf = MedianFinder()
    for v in [2, 3, 4]:
        mf.addNum(v)
    print(mf.findMedian())  # 3.0

def _run_test3():
    mf = MedianFinder()
    for v in [2, 3]:
        mf.addNum(v)
    print(mf.findMedian())  # 2.5

def _run_test4():
    mf = MedianFinder()
    mf.addNum(-100000)
    print(mf.findMedian())  # -100000.0

def _run_test5():
    mf = MedianFinder()
    mf.addNum(5)
    print(mf.findMedian())  # 5.0
    mf.addNum(15)
    print(mf.findMedian())  # 10.0
    mf.addNum(1)
    print(mf.findMedian())  # 5.0
    mf.addNum(3)
    print(mf.findMedian())  # 4.0


if __name__ == "__main__":
    _run_test1()
    _run_test2()
    _run_test3()
    _run_test4()
    _run_test5()