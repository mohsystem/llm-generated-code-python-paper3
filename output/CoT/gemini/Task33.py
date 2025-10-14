def queue_time(customers, n):
    """
    Calculates the total time required for all customers to check out.

    :param customers: A list of positive integers representing the time each customer needs.
    :param n: A positive integer, the number of checkout tills.
    :return: An integer, the total time required.
    """
    if not customers:
        return 0
    
    tills = [0] * n
    
    for customer_time in customers:
        # Find the till with the minimum current wait time
        min_till_index = tills.index(min(tills))
        # Add the customer's time to that till
        tills[min_till_index] += customer_time
        
    # The total time is the maximum time among all tills
    return max(tills)

if __name__ == '__main__':
    # Test Case 1
    print(queue_time([5, 3, 4], 1))
    # Test Case 2
    print(queue_time([10, 2, 3, 3], 2))
    # Test Case 3
    print(queue_time([2, 3, 10], 2))
    # Test Case 4
    print(queue_time([], 1))
    # Test Case 5
    print(queue_time([1, 2, 3, 4, 5], 100))