def knapsack(capacity, weights, values):
    n = len(values)
    if n == 0:
        return 0
    
    dp = [0] * (capacity + 1)
    
    for i in range(n):
        for w in range(capacity, weights[i] - 1, -1):
            dp[w] = max(dp[w], values[i] + dp[w - weights[i]])
            
    return dp[capacity]

def main():
    # Test Case 1
    values1 = [60, 100, 120]
    weights1 = [10, 20, 30]
    capacity1 = 50
    print(f"Test Case 1: Maximum value = {knapsack(capacity1, weights1, values1)}")

    # Test Case 2
    values2 = [10, 20, 30]
    weights2 = [5, 10, 15]
    capacity2 = 50
    print(f"Test Case 2: Maximum value = {knapsack(capacity2, weights2, values2)}")

    # Test Case 3
    values3 = [10, 40, 30, 50]
    weights3 = [5, 4, 6, 3]
    capacity3 = 10
    print(f"Test Case 3: Maximum value = {knapsack(capacity3, weights3, values3)}")
    
    # Test Case 4
    values4 = []
    weights4 = []
    capacity4 = 10
    print(f"Test Case 4: Maximum value = {knapsack(capacity4, weights4, values4)}")

    # Test Case 5
    values5 = [60, 100, 120]
    weights5 = [10, 20, 30]
    capacity5 = 0
    print(f"Test Case 5: Maximum value = {knapsack(capacity5, weights5, values5)}")

if __name__ == "__main__":
    main()