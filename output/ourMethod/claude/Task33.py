
from typing import List

def queue_time(customers: List[int], n: int) -> int:
    # Input validation
    if customers is None or n <= 0:
        return 0
    
    if len(customers) == 0:
        return 0
    
    # Validate all customer times are non-negative
    for time in customers:
        if not isinstance(time, int) or time < 0:
            raise ValueError("Customer time must be a non-negative integer")
    
    # Create list to track time at each till
    tills = [0] * min(n, len(customers))
    
    # Assign each customer to the till with minimum time
    for customer_time in customers:
        # Find till with minimum time
        min_index = 0
        min_time = tills[0]
        for i in range(1, len(tills)):
            if tills[i] < min_time:
                min_time = tills[i]
                min_index = i
        # Assign customer to that till
        tills[min_index] += customer_time
    
    # Return maximum time among all tills
    return max(tills)

def main():
    # Test case 1
    test1 = [5, 3, 4]
    print(f"Test 1: {queue_time(test1, 1)} (expected: 12)")
    
    # Test case 2
    test2 = [10, 2, 3, 3]
    print(f"Test 2: {queue_time(test2, 2)} (expected: 10)")
    
    # Test case 3
    test3 = [2, 3, 10]
    print(f"Test 3: {queue_time(test3, 2)} (expected: 12)")
    
    # Test case 4
    test4 = []
    print(f"Test 4: {queue_time(test4, 1)} (expected: 0)")
    
    # Test case 5
    test5 = [1, 2, 3, 4, 5]
    print(f"Test 5: {queue_time(test5, 5)} (expected: 5)")

if __name__ == "__main__":
    main()
