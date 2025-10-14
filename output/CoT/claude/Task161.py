
def knapsack(capacity, weights, values):
    # Input validation
    if capacity < 0:
        raise ValueError("Capacity cannot be negative")
    if weights is None or values is None:
        raise ValueError("Weights and values lists cannot be None")
    if len(weights) != len(values):
        raise ValueError("Weights and values lists must have the same length")
    if len(weights) == 0:
        return 0
    
    # Validate individual weights and values
    for i in range(len(weights)):
        if weights[i] < 0 or values[i] < 0:
            raise ValueError("Weights and values must be non-negative")
    
    n = len(weights)
    
    # Prevent memory issues for very large capacity
    if capacity > 1000000:
        raise ValueError("Capacity is too large")
    
    # Dynamic programming approach
    dp = [[0 for _ in range(capacity + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(capacity + 1):
            if weights[i - 1] <= w:
                dp[i][w] = max(
                    values[i - 1] + dp[i - 1][w - weights[i - 1]],
                    dp[i - 1][w]
                )
            else:
                dp[i][w] = dp[i - 1][w]
    
    return dp[n][capacity]


if __name__ == "__main__":
    try:
        # Test case 1: Basic case
        weights1 = [2, 3, 4, 5]
        values1 = [3, 4, 5, 6]
        capacity1 = 5
        print(f"Test 1 - Capacity: {capacity1}, Max Value: {knapsack(capacity1, weights1, values1)}")
        
        # Test case 2: Single item
        weights2 = [10]
        values2 = [100]
        capacity2 = 15
        print(f"Test 2 - Capacity: {capacity2}, Max Value: {knapsack(capacity2, weights2, values2)}")
        
        # Test case 3: No items fit
        weights3 = [10, 20, 30]
        values3 = [60, 100, 120]
        capacity3 = 5
        print(f"Test 3 - Capacity: {capacity3}, Max Value: {knapsack(capacity3, weights3, values3)}")
        
        # Test case 4: All items fit
        weights4 = [1, 2, 3]
        values4 = [10, 20, 30]
        capacity4 = 10
        print(f"Test 4 - Capacity: {capacity4}, Max Value: {knapsack(capacity4, weights4, values4)}")
        
        # Test case 5: Zero capacity
        weights5 = [5, 10, 15]
        values5 = [50, 100, 150]
        capacity5 = 0
        print(f"Test 5 - Capacity: {capacity5}, Max Value: {knapsack(capacity5, weights5, values5)}")
        
    except Exception as e:
        print(f"Error: {e}")
