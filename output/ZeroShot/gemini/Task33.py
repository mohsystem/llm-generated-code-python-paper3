def queueTime(customers, n):
    """
    Calculates the total time required for all customers to check out.

    :param customers: A list of positive integers representing the time each customer needs.
    :param n: The number of checkout tills.
    :return: The total time required.
    """
    if not customers:
        return 0

    # Initialize a list to track the time for each till
    tills = [0] * n

    for customer_time in customers:
        # Find the till that will be free the soonest (the one with the minimum current time)
        min_time_till_index = tills.index(min(tills))
        
        # Assign the next customer to this till
        tills[min_time_till_index] += customer_time

    # The total time is the time when the last customer finishes,
    # which is the maximum time among all tills.
    return max(tills)

# main method with 5 test cases
if __name__ == '__main__':
    # Test Case 1
    print(queueTime([5, 3, 4], 1))  # Expected: 12

    # Test Case 2
    print(queueTime([10, 2, 3, 3], 2))  # Expected: 10

    # Test Case 3
    print(queueTime([2, 3, 10], 2))  # Expected: 12
    
    # Test Case 4 (empty queue)
    print(queueTime([], 1))  # Expected: 0

    # Test Case 5 (more tills than customers)
    print(queueTime([1, 2, 3, 4, 5], 100))  # Expected: 5