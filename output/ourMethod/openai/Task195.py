from __future__ import annotations
import heapq
from typing import List


class MedianFinder:
    def __init__(self) -> None:
        self.lower: List[int] = []  # max-heap via negative values
        self.upper: List[int] = []  # min-heap

    def addNum(self, num: int) -> None:
        if not isinstance(num, int):
            raise TypeError("num must be int")
        if num < -100000 or num > 100000:
            raise ValueError("num out of allowed range")
        if not self.lower or num <= -self.lower[0]:
            heapq.heappush(self.lower, -num)
        else:
            heapq.heappush(self.upper, num)
        self._rebalance()

    def findMedian(self) -> float:
        if not self.lower and not self.upper:
            raise RuntimeError("No elements present")
        if len(self.lower) > len(self.upper):
            return float(-self.lower[0])
        return (-self.lower[0] + self.upper[0]) / 2.0

    def _rebalance(self) -> None:
        if len(self.lower) > len(self.upper) + 1:
            heapq.heappush(self.upper, -heapq.heappop(self.lower))
        elif len(self.upper) > len(self.lower):
            heapq.heappush(self.lower, -heapq.heappop(self.upper))


def run_tests() -> None:
    # Test 1
    mf1 = MedianFinder()
    mf1.addNum(1)
    mf1.addNum(2)
    print(mf1.findMedian())  # 1.5
    mf1.addNum(3)
    print(mf1.findMedian())  # 2.0

    # Test 2
    mf2 = MedianFinder()
    for x in [2, 3, 4]:
        mf2.addNum(x)
    print(mf2.findMedian())  # 3.0

    # Test 3
    mf3 = MedianFinder()
    for x in [2, 3]:
        mf3.addNum(x)
    print(mf3.findMedian())  # 2.5

    # Test 4
    mf4 = MedianFinder()
    for x in [-5, -1, -3, -4]:
        mf4.addNum(x)
    print(mf4.findMedian())  # -3.5

    # Test 5
    mf5 = MedianFinder()
    for x in [5, 10, -1, 20, 3]:
        mf5.addNum(x)
    print(mf5.findMedian())  # 5.0


if __name__ == "__main__":
    run_tests()