import typing

def queue_time(customers: typing.List[int], n: int) -> int:
    """
    Calculates the total time required for all customers to check out.

    :param customers: A list of positive integers representing the time each customer needs.
    :param n: The number of checkout tills.
    :return: The total time required.
    """
    if not customers:
        return 0
    
    tills = [0] * n
    
    for customer_time in customers:
        # Find the till that will be free earliest
        min_till_idx = tills.index(min(tills))
        # Assign the next customer to this till
        tills[min_till_idx] += customer_time
        
    # The total time is the time the last till finishes
    return max(tills)

if __name__ == '__main__':
    # Test cases
    print(queue_time([5, 3, 4], 1))        # Expected: 12
    print(queue_time([10, 2, 3, 3], 2))    # Expected: 10
    print(queue_time([2, 3, 10], 2))       # Expected: 12
    print(queue_time([], 1))               # Expected: 0
    print(queue_time([1, 2, 3, 4, 5], 100)) # Expected: 5