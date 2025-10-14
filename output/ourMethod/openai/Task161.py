from typing import List

def knapsack(capacity: int, weights: List[int], values: List[int]) -> int:
    if not isinstance(capacity, int) or capacity < 0:
        raise ValueError("Capacity must be a non-negative integer.")
    if weights is None or values is None:
        raise ValueError("Weights and values must not be None.")
    if len(weights) != len(values):
        raise ValueError("Weights and values must have the same length.")
    for w in weights:
        if not isinstance(w, int) or w < 0:
            raise ValueError("All weights must be non-negative integers.")
    # Values can be any integers

    dp = [0] * (capacity + 1)
    for wt, val in zip(weights, values):
        if wt > capacity:
            continue
        for w in range(capacity, wt - 1, -1):
            cand = dp[w - wt] + val
            if cand > dp[w]:
                dp[w] = cand
    return dp[capacity]

def _run_test(test_num: int, capacity: int, weights: List[int], values: List[int], expected: int) -> None:
    result = knapsack(capacity, weights, values)
    print(f"Test {test_num} -> result={result} expected={expected}")

if __name__ == "__main__":
    # Test 1: Classic example
    _run_test(1, 50, [10, 20, 30], [60, 100, 120], 220)

    # Test 2: Empty items
    _run_test(2, 10, [], [], 0)

    # Test 3: Zero capacity
    _run_test(3, 0, [1, 2, 3], [10, 20, 30], 0)

    # Test 4: Items heavier than capacity
    _run_test(4, 5, [6, 7, 8], [10, 20, 30], 0)

    # Test 5: Mixed items
    _run_test(5, 7, [1, 3, 4, 5], [1, 4, 5, 7], 9)