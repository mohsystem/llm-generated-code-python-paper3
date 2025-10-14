from typing import List

def knapsack(capacity: int, weights: List[int], values: List[int]) -> int:
    """
    Solves the 0/1 knapsack problem.

    Args:
        capacity: The maximum weight capacity of the knapsack.
        weights: A list of weights of the items.
        values: A list of values of the items.

    Returns:
        The maximum value that can be put into the knapsack, or -1 if input is invalid.
    """
    # Input validation
    if not (isinstance(capacity, int) and capacity >= 0 and
            isinstance(weights, list) and isinstance(values, list) and
            len(weights) == len(values) and
            all(isinstance(w, int) and w >= 0 for w in weights) and
            all(isinstance(v, int) and v >= 0 for v in values)):
        return -1

    n = len(weights)
    if n == 0 or capacity == 0:
        return 0

    # dp[i][w] will be the maximum value that can be obtained with a
    # capacity w using the first i items.
    dp = [[0 for _ in range(capacity + 1)] for _ in range(n + 1)]

    # Build table dp[][] in a bottom-up manner
    for i in range(1, n + 1):
        for w in range(1, capacity + 1):
            # Current item's weight and value (i-1 is the index in original lists)
            current_weight = weights[i - 1]
            current_value = values[i - 1]

            if current_weight <= w:
                # Two choices:
                # 1. Include the current item
                # 2. Exclude the current item
                dp[i][w] = max(current_value + dp[i - 1][w - current_weight], dp[i - 1][w])
            else:
                # Cannot include the current item
                dp[i][w] = dp[i - 1][w]

    return dp[n][capacity]

if __name__ == '__main__':
    # Test Case 1: Standard case
    weights1 = [10, 20, 30]
    values1 = [60, 100, 120]
    capacity1 = 50
    print(f"Test Case 1: Max value = {knapsack(capacity1, weights1, values1)}") # Expected: 220

    # Test Case 2: No items
    weights2 = []
    values2 = []
    capacity2 = 10
    print(f"Test Case 2: Max value = {knapsack(capacity2, weights2, values2)}") # Expected: 0

    # Test Case 3: Capacity too small for any item
    weights3 = [10, 20]
    values3 = [100, 200]
    capacity3 = 5
    print(f"Test Case 3: Max value = {knapsack(capacity3, weights3, values3)}") # Expected: 0

    # Test Case 4: All items fit
    weights4 = [10, 20, 30]
    values4 = [60, 100, 120]
    capacity4 = 100
    print(f"Test Case 4: Max value = {knapsack(capacity4, weights4, values4)}") # Expected: 280

    # Test Case 5: Complex case
    weights5 = [5, 4, 6, 3]
    values5 = [10, 40, 30, 50]
    capacity5 = 10
    print(f"Test Case 5: Max value = {knapsack(capacity5, weights5, values5)}") # Expected: 90