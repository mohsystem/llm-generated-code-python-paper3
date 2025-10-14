def queueTime(customers, n):
    """
    Calculates the total time required for all customers to check out.

    :param customers: A list of positive integers representing the queue.
    :param n: The number of checkout tills.
    :return: The total time required.
    """
    tills = [0] * n
    
    for customer_time in customers:
        # Find the till that will be free the soonest and assign customer
        min_till_idx = tills.index(min(tills))
        tills[min_till_idx] += customer_time
        
    # The total time is the time the last till becomes free
    return max(tills) if tills else 0

if __name__ == '__main__':
    # Test cases
    print(queueTime([], 1))  # Expected: 0
    print(queueTime([5, 3, 4], 1))  # Expected: 12
    print(queueTime([10, 2, 3, 3], 2))  # Expected: 10
    print(queueTime([2, 3, 10], 2))  # Expected: 12
    print(queueTime([1, 2, 3, 4, 5], 100))  # Expected: 5