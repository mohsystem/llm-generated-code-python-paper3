import heapq

def queueTime(customers, n):
    if n <= 0:
        raise ValueError("n must be positive")
    times = [0] * n
    heapq.heapify(times)
    for t in customers:
        shortest = heapq.heappop(times)
        heapq.heappush(times, shortest + t)
    return max(times) if times else 0

if __name__ == "__main__":
    tests = [
        ([5, 3, 4], 1),
        ([10, 2, 3, 3], 2),
        ([2, 3, 10], 2),
        ([], 1),
        ([1, 2, 3, 4, 5], 100),
    ]
    for customers, n in tests:
        print(queueTime(customers, n))