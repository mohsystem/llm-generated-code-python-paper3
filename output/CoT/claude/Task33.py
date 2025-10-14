
def queue_time(customers, n):
    # Input validation
    if not customers or n <= 0:
        return 0
    
    # If number of tills is greater than or equal to customers,
    # return the maximum time among all customers
    if n >= len(customers):
        return max(customers)
    
    # Create a list to represent the tills and their busy time
    tills = [0] * n
    
    # Assign each customer to the till that will be free first
    for customer_time in customers:
        # Find the till with minimum time
        min_index = tills.index(min(tills))
        # Assign customer to the till with minimum time
        tills[min_index] += customer_time
    
    # Return the maximum time among all tills
    return max(tills)


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", queue_time([5, 3, 4], 1))  # Expected: 12
    
    # Test case 2
    print("Test 2:", queue_time([10, 2, 3, 3], 2))  # Expected: 10
    
    # Test case 3
    print("Test 3:", queue_time([2, 3, 10], 2))  # Expected: 12
    
    # Test case 4
    print("Test 4:", queue_time([], 1))  # Expected: 0
    
    # Test case 5
    print("Test 5:", queue_time([1, 2, 3, 4, 5], 5))  # Expected: 5
