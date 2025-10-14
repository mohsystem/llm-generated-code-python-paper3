
import heapq

def queue_time(customers, n):
    if not customers or n <= 0:
        return 0
    
    if n >= len(customers):
        return max(customers) if customers else 0
    
    # Use a min heap to track the finish time of each till
    tills = [0] * n
    heapq.heapify(tills)
    
    # Process each customer
    for customer_time in customers:
        # Get the till that will be free first
        earliest_free_till = heapq.heappop(tills)
        # Add the customer to that till
        heapq.heappush(tills, earliest_free_till + customer_time)
    
    # The total time is when the last till finishes
    return max(tills)

# Main function with test cases
if __name__ == "__main__":
    # Test case 1
    test1 = [5, 3, 4]
    print(f"Test 1: {queue_time(test1, 1)} (Expected: 12)")
    
    # Test case 2
    test2 = [10, 2, 3, 3]
    print(f"Test 2: {queue_time(test2, 2)} (Expected: 10)")
    
    # Test case 3
    test3 = [2, 3, 10]
    print(f"Test 3: {queue_time(test3, 2)} (Expected: 12)")
    
    # Test case 4
    test4 = []
    print(f"Test 4: {queue_time(test4, 1)} (Expected: 0)")
    
    # Test case 5
    test5 = [1, 2, 3, 4, 5]
    print(f"Test 5: {queue_time(test5, 100)} (Expected: 5)")
