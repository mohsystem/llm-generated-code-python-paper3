import heapq

def queueTime(customers, n):
    if not customers or n <= 0:
        return 0
    n_tills = min(n, len(customers))
    heap = [max(0, customers[i]) for i in range(n_tills)]
    heapq.heapify(heap)
    for i in range(n_tills, len(customers)):
        t = heapq.heappop(heap)
        heapq.heappush(heap, t + max(0, customers[i]))
    return int(max(heap) if heap else 0)

if __name__ == "__main__":
    # 5 test cases
    print(queueTime([5,3,4], 1))           # 12
    print(queueTime([10,2,3,3], 2))        # 10
    print(queueTime([2,3,10], 2))          # 12
    print(queueTime([], 1))                # 0
    print(queueTime([1,2,3,4,5], 100))     # 5