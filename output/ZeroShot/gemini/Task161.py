def knapsack(capacity, weights, values):
    """
    Solves the 0/1 knapsack problem using dynamic programming.

    Args:
        capacity: The maximum weight capacity of the knapsack.
        weights: A list of weights of the items.
        values: A list of values of the items.

    Returns:
        The maximum value that can be put into the knapsack.
    """
    # --- Secure Code: Input Validation ---
    if not isinstance(capacity, int) or capacity < 0:
        # In a real-world app, raising ValueError would be better.
        return 0
    if not isinstance(weights, list) or not isinstance(values, list) or len(weights) != len(values):
        return 0
    
    n = len(values)
    if n == 0 or capacity == 0:
        return 0

    # dp[w] will be the maximum value that can be obtained for a knapsack of capacity w
    dp = [0] * (capacity + 1)

    # Build table dp[] in a bottom-up manner
    for i in range(n):
        # --- Secure Code: Check for invalid item properties ---
        if weights[i] < 0 or values[i] < 0:
            # Skip items with negative weight or value.
            continue
            
        # Traverse backwards to ensure each item is considered only once (0/1 property)
        for w in range(capacity, weights[i] - 1, -1):
            dp[w] = max(dp[w], values[i] + dp[w - weights[i]])

    return dp[capacity]

def main():
    """Runs test cases for the knapsack problem."""
    # Test Case 1: General case
    capacity1 = 50
    values1 = [60, 100, 120]
    weights1 = [10, 20, 30]
    print(f"Test Case 1: Max value = {knapsack(capacity1, weights1, values1)}")

    # Test Case 2: Empty items
    capacity2 = 10
    values2 = []
    weights2 = []
    print(f"Test Case 2: Max value = {knapsack(capacity2, weights2, values2)}")

    # Test Case 3: Zero capacity
    capacity3 = 0
    values3 = [60, 100]
    weights3 = [10, 20]
    print(f"Test Case 3: Max value = {knapsack(capacity3, weights3, values3)}")

    # Test Case 4: Items that partially fit
    capacity4 = 5
    values4 = [3, 4, 5, 6]
    weights4 = [2, 3, 4, 5]
    print(f"Test Case 4: Max value = {knapsack(capacity4, weights4, values4)}")

    # Test Case 5: More complex case
    capacity5 = 10
    values5 = [10, 40, 30, 50]
    weights5 = [5, 4, 6, 3]
    print(f"Test Case 5: Max value = {knapsack(capacity5, weights5, values5)}")

if __name__ == "__main__":
    main()