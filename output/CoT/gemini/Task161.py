def knapSack(capacity, weights, values):
    """
    Solves the 0/1 knapsack problem using dynamic programming.
    :param capacity: The maximum weight capacity of the knapsack.
    :param weights: A list of weights of the items.
    :param values: A list of values of the items.
    :return: The maximum value that can be put into the knapsack.
    """
    n = len(weights)
    # Basic input validation
    if n == 0 or capacity <= 0 or len(values) != n:
        return 0

    # dp[w] will be storing the maximum value that can be obtained with knapsack capacity w.
    dp = [0] * (capacity + 1)

    # Traverse through all items
    for i in range(n):
        # Traverse dp array from right to left to prevent using the same item multiple times
        for w in range(capacity, weights[i] - 1, -1):
            dp[w] = max(dp[w], values[i] + dp[w - weights[i]])
    
    return dp[capacity]

if __name__ == '__main__':
    # Test Case 1: Standard case
    values1 = [60, 100, 120]
    weights1 = [10, 20, 30]
    capacity1 = 50
    print(f"Test Case 1: Maximum value is {knapSack(capacity1, weights1, values1)}")

    # Test Case 2: Small capacity with more items
    values2 = [10, 40, 30, 50]
    weights2 = [5, 4, 6, 3]
    capacity2 = 10
    print(f"Test Case 2: Maximum value is {knapSack(capacity2, weights2, values2)}")

    # Test Case 3: All items fit
    values3 = [60, 100, 120]
    weights3 = [10, 20, 30]
    capacity3 = 100
    print(f"Test Case 3: Maximum value is {knapSack(capacity3, weights3, values3)}")

    # Test Case 4: No items
    values4 = []
    weights4 = []
    capacity4 = 50
    print(f"Test Case 4: Maximum value is {knapSack(capacity4, weights4, values4)}")

    # Test Case 5: Zero capacity
    values5 = [60, 100, 120]
    weights5 = [10, 20, 30]
    capacity5 = 0
    print(f"Test Case 5: Maximum value is {knapSack(capacity5, weights5, values5)}")