# Step 1-5 (Chain-of-Through) summarized:
# 1) Problem: Compute total checkout time with n tills and a single queue.
# 2) Security: Validate n; handle empty inputs safely.
# 3) Implementation: Use heapq as a min-heap to track till availability.
# 4) Review: Checked edge cases and ensured no unsafe operations.
# 5) Final: Function returns integer; includes 5 test cases.

import heapq

def queueTime(customers, n):
    if not customers:
        return 0
    if n <= 0:
        raise ValueError("Number of tills must be positive.")
    tills = [0] * n
    heapq.heapify(tills)
    for t in customers:
        earliest = heapq.heappop(tills)
        heapq.heappush(tills, earliest + t)
    return max(tills) if tills else 0

if __name__ == "__main__":
    tests = [
        ([5, 3, 4], 1, 12),
        ([10, 2, 3, 3], 2, 10),
        ([2, 3, 10], 2, 12),
        ([], 1, 0),
        ([1, 2, 3, 4, 5], 100, 5),
    ]
    for i, (arr, n, exp) in enumerate(tests, 1):
        res = queueTime(arr, n)
        print(f"Test {i}: {res} (expected {exp})")