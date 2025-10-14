
def knapsack(capacity, weights, values):
    if capacity <= 0 or not weights or not values or len(weights) != len(values):
        return 0
    
    n = len(weights)
    dp = [[0 for _ in range(capacity + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(1, capacity + 1):
            if weights[i - 1] <= w:
                dp[i][w] = max(dp[i - 1][w], 
                              values[i - 1] + dp[i - 1][w - weights[i - 1]])
            else:
                dp[i][w] = dp[i - 1][w]
    
    return dp[n][capacity]


if __name__ == "__main__":
    # Test case 1
    capacity1 = 50
    weights1 = [10, 20, 30]
    values1 = [60, 100, 120]
    print(f"Test 1 - Capacity: {capacity1}, Max Value: {knapsack(capacity1, weights1, values1)}")
    
    # Test case 2
    capacity2 = 10
    weights2 = [5, 4, 6, 3]
    values2 = [10, 40, 30, 50]
    print(f"Test 2 - Capacity: {capacity2}, Max Value: {knapsack(capacity2, weights2, values2)}")
    
    # Test case 3
    capacity3 = 7
    weights3 = [1, 3, 4, 5]
    values3 = [1, 4, 5, 7]
    print(f"Test 3 - Capacity: {capacity3}, Max Value: {knapsack(capacity3, weights3, values3)}")
    
    # Test case 4
    capacity4 = 15
    weights4 = [2, 3, 5, 7, 1]
    values4 = [10, 5, 15, 7, 6]
    print(f"Test 4 - Capacity: {capacity4}, Max Value: {knapsack(capacity4, weights4, values4)}")
    
    # Test case 5
    capacity5 = 8
    weights5 = [2, 3, 4, 5]
    values5 = [3, 4, 5, 6]
    print(f"Test 5 - Capacity: {capacity5}, Max Value: {knapsack(capacity5, weights5, values5)}")
