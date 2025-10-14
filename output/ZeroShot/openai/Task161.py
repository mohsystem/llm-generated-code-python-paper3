from typing import List

MAX_CAPACITY = 2_000_000

def max_knapsack_value(capacity: int, weights: List[int], values: List[int]) -> int:
    if capacity < 0:
        return 0
    if weights is None or values is None or len(weights) != len(values):
        return -1
    if capacity > MAX_CAPACITY:
        return -1
    n = len(weights)
    for i in range(n):
        if weights[i] < 0 or values[i] < 0:
            return -1
    dp = [0] * (capacity + 1)
    for wt, val in zip(weights, values):
        if wt <= capacity:
            for c in range(capacity, wt - 1, -1):
                base = dp[c - wt]
                candidate = base + val
                # Python ints are unbounded; no overflow check needed, but keep logic consistent
                if candidate > dp[c]:
                    dp[c] = candidate
    return dp[capacity]

if __name__ == "__main__":
    # Test case 1
    cap1 = 50
    w1 = [10, 20, 30]
    v1 = [60, 100, 120]
    print(max_knapsack_value(cap1, w1, v1))  # Expected 220

    # Test case 2
    cap2 = 7
    w2 = [1, 3, 4, 5]
    v2 = [1, 4, 5, 7]
    print(max_knapsack_value(cap2, w2, v2))  # Expected 9

    # Test case 3
    cap3 = 0
    w3 = [1, 2, 3]
    v3 = [10, 15, 40]
    print(max_knapsack_value(cap3, w3, v3))  # Expected 0

    # Test case 4
    cap4 = 10
    w4 = [3, 4, 5, 9, 4]
    v4 = [4, 5, 7, 10, 6]
    print(max_knapsack_value(cap4, w4, v4))  # Expected 13

    # Test case 5
    cap5 = 15
    w5 = [12, 2, 1, 1, 4]
    v5 = [4, 2, 2, 1, 10]
    print(max_knapsack_value(cap5, w5, v5))  # Expected 15