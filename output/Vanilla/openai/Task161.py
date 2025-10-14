class Task161:
    @staticmethod
    def knapsack(capacity, weights, values):
        if capacity <= 0 or not weights or not values or len(weights) != len(values):
            return 0
        dp = [0] * (capacity + 1)
        for w, v in zip(weights, values):
            for c in range(capacity, w - 1, -1):
                dp[c] = max(dp[c], dp[c - w] + v)
        return dp[capacity]

if __name__ == "__main__":
    # Test case 1
    cap1 = 5
    w1 = [1, 2, 3]
    v1 = [6, 10, 12]
    print(Task161.knapsack(cap1, w1, v1))  # Expected 22

    # Test case 2
    cap2 = 3
    w2 = [4, 5]
    v2 = [7, 8]
    print(Task161.knapsack(cap2, w2, v2))  # Expected 0

    # Test case 3
    cap3 = 0
    w3 = [1, 2]
    v3 = [10, 20]
    print(Task161.knapsack(cap3, w3, v3))  # Expected 0

    # Test case 4
    cap4 = 4
    w4 = [4]
    v4 = [10]
    print(Task161.knapsack(cap4, w4, v4))  # Expected 10

    # Test case 5
    cap5 = 10
    w5 = [2, 5, 1, 3, 4]
    v5 = [3, 4, 7, 8, 9]
    print(Task161.knapsack(cap5, w5, v5))  # Expected 27