
from typing import List, Tuple
import sys

MAX_CAPACITY = 1000000
MAX_ITEMS = 10000
MAX_WEIGHT = 1000000
MAX_VALUE = 1000000


def knapsack(capacity: int, items: List[Tuple[int, int]]) -> int:
    """\n    Solves the 0/1 knapsack problem.\n    \n    Args:\n        capacity: Maximum weight capacity of the knapsack\n        items: List of tuples (weight, value) for each item\n    \n    Returns:\n        Maximum value that can be achieved\n    """
    if not isinstance(capacity, int):
        raise TypeError("Capacity must be an integer")
    
    if capacity < 0 or capacity > MAX_CAPACITY:
        raise ValueError(f"Capacity must be between 0 and {MAX_CAPACITY}")
    
    if not isinstance(items, list):
        raise TypeError("Items must be a list")
    
    if len(items) > MAX_ITEMS:
        raise ValueError(f"Number of items exceeds maximum allowed: {MAX_ITEMS}")
    
    if not items or capacity == 0:
        return 0
    
    for i, item in enumerate(items):
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError(f"Item at index {i} must be a tuple of (weight, value)")
        
        weight, value = item
        
        if not isinstance(weight, int) or not isinstance(value, int):
            raise TypeError(f"Weight and value at index {i} must be integers")
        
        if weight < 0 or weight > MAX_WEIGHT:
            raise ValueError(f"Weight at index {i} must be between 0 and {MAX_WEIGHT}")
        
        if value < 0 or value > MAX_VALUE:
            raise ValueError(f"Value at index {i} must be between 0 and {MAX_VALUE}")
    
    n = len(items)
    dp = [0] * (capacity + 1)
    
    for i in range(n):
        weight, value = items[i]
        
        for w in range(capacity, weight - 1, -1):
            new_value = dp[w - weight] + value
            if new_value > dp[w]:
                dp[w] = new_value
    
    return dp[capacity]


def main() -> None:
    try:
        # Test case 1: Basic case
        items1 = [(2, 3), (3, 4), (4, 5), (5, 6)]
        result1 = knapsack(5, items1)
        print(f"Test 1 - Capacity 5: {result1}")
        
        # Test case 2: Empty items
        items2 = []
        result2 = knapsack(10, items2)
        print(f"Test 2 - Empty items: {result2}")
        
        # Test case 3: Zero capacity
        items3 = [(5, 10)]
        result3 = knapsack(0, items3)
        print(f"Test 3 - Zero capacity: {result3}")
        
        # Test case 4: Multiple items
        items4 = [(1, 1), (3, 4), (4, 5), (5, 7)]
        result4 = knapsack(7, items4)
        print(f"Test 4 - Capacity 7: {result4}")
        
        # Test case 5: Large values
        items5 = [(10, 60), (20, 100), (30, 120)]
        result5 = knapsack(50, items5)
        print(f"Test 5 - Capacity 50: {result5}")
        
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
