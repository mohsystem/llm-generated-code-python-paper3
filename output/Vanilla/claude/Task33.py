
import heapq

def queue_time(customers, n):
    if not customers or n <= 0:
        return 0
    
    if n >= len(customers):
        return max(customers)
    
    # Use a min heap to track till finish times
    tills = [0] * n
    heapq.heapify(tills)
    
    # Process each customer
    for customer_time in customers:
        # Get the till that will be free first
        earliest_free = heapq.heappop(tills)
        # Add customer time to that till
        heapq.heappush(tills, earliest_free + customer_time)
    
    # Return the maximum time (last till to finish)
    return max(tills)

if __name__ == "__main__":
    # Test case 1
    print(f"Test 1: {queue_time([5, 3, 4], 1)} (Expected: 12)")
    
    # Test case 2
    print(f"Test 2: {queue_time([10, 2, 3, 3], 2)} (Expected: 10)")
    
    # Test case 3
    print(f"Test 3: {queue_time([2, 3, 10], 2)} (Expected: 12)")
    
    # Test case 4
    print(f"Test 4: {queue_time([1, 2, 3, 4, 5], 3)} (Expected: 6)")
    
    # Test case 5
    print(f"Test 5: {queue_time([], 1)} (Expected: 0)")
