from typing import List
import heapq

def queueTime(customers: List[int], n: int) -> int:
    if not isinstance(customers, list):
        raise TypeError("customers must be a list")
    if not isinstance(n, int) or n <= 0:
        raise ValueError("n must be a positive integer")
    for t in customers:
        if not isinstance(t, int) or t < 0:
            raise ValueError("customer times must be non-negative integers")
    if not customers:
        return 0
    k = min(n, len(customers))
    heap = customers[:k]
    heapq.heapify(heap)
    for t in customers[k:]:
        smallest = heapq.heappop(heap)
        heapq.heappush(heap, smallest + t)
    return max(heap) if heap else 0

if __name__ == "__main__":
    tests = [
        ([5, 3, 4], 1),
        ([10, 2, 3, 3], 2),
        ([2, 3, 10], 2),
        ([], 1),
        ([1, 2, 3, 4, 5], 100),
    ]
    for i, (cust, tills) in enumerate(tests, 1):
        print(f"Test {i} result: {queueTime(cust, tills)}")