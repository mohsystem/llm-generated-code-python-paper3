from typing import List

def knapsack(capacity: int, weights: List[int], values: List[int]) -> int:
    if capacity <= 0 or weights is None or values is None or len(weights) != len(values):
        return 0
    n = len(weights)
    dp = [0] * (capacity + 1)
    for i in range(n):
        w = weights[i]
        v = values[i]
        if w is None or v is None or w <= 0 or v < 0:
            continue
        for c in range(capacity, w - 1, -1):
            cand = dp[c - w] + v
            if cand > dp[c]:
                dp[c] = cand
    return dp[capacity]

if __name__ == "__main__":
    # Test case 1
    cap1 = 50
    w1 = [10, 20, 30]
    v1 = [60, 100, 120]
    print(knapsack(cap1, w1, v1))  # Expected: 220

    # Test case 2
    cap2 = 0
    w2 = [5, 10]
    v2 = [10, 20]
    print(knapsack(cap2, w2, v2))  # Expected: 0

    # Test case 3
    cap3 = 7
    w3 = [1, 3, 4, 5]
    v3 = [1, 4, 5, 7]
    print(knapsack(cap3, w3, v3))  # Expected: 9

    # Test case 4
    cap4 = 10
    w4 = [6, 3, 4, 2]
    v4 = [30, 14, 16, 9]
    print(knapsack(cap4, w4, v4))  # Expected: 46

    # Test case 5
    cap5 = 5
    w5 = [4, 2, 3]
    v5 = [10, 4, 7]
    print(knapsack(cap5, w5, v5))  # Expected: 11