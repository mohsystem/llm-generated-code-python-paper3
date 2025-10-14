import heapq

class MedianFinder:
    def __init__(self):
        # max-heap for lower half (store negatives)
        self.lower = []
        # min-heap for upper half
        self.upper = []

    def addNum(self, num: int) -> None:
        # Step 1: push to lower (as negative for max-heap behavior)
        heapq.heappush(self.lower, -num)
        # Step 2: balance, move the largest from lower to upper
        moved = -heapq.heappop(self.lower)
        heapq.heappush(self.upper, moved)
        # Step 3: ensure lower has equal or one more element than upper
        if len(self.upper) > len(self.lower):
            heapq.heappush(self.lower, -heapq.heappop(self.upper))

    def findMedian(self) -> float:
        if not self.lower:
            raise ValueError("No elements to find median.")
        if len(self.lower) == len(self.upper):
            return (-self.lower[0] + self.upper[0]) / 2.0
        else:
            return float(-self.lower[0])

class Task195:
    @staticmethod
    def run_tests():
        def run_case(name, ops, vals, expected):
            mf = MedianFinder()
            results = []
            vi = 0
            for op in ops:
                if op == 0:
                    mf.addNum(vals[vi]); vi += 1
                else:
                    results.append(mf.findMedian())
            print(f"{name} results: {results}")
            if expected is not None:
                print(f"{name} expected: {expected}")
            print("----")

        # Test 1: Example
        run_case("Test1", [0,0,1,0,1], [1,2,3], [1.5, 2.0])
        # Test 2: Single element
        run_case("Test2", [0,1], [-100000], [-100000.0])
        # Test 3: Even count increasing
        run_case("Test3", [0,0,0,0,1], [5,10,15,20], [12.5])
        # Test 4: Duplicates
        run_case("Test4", [0,0,0,0,0,1], [2,2,2,3,4], [2.0])
        # Test 5: Mixed negatives and positives
        run_case("Test5", [0,0,0,0,1], [-5,-1,-3,7], [-2.0])

if __name__ == "__main__":
    Task195.run_tests()