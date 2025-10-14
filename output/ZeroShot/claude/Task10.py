
def get_sum(a, b):
    if a == b:
        return a
    
    min_val = min(a, b)
    max_val = max(a, b)
    
    # Using arithmetic progression formula: sum = n * (first + last) / 2
    n = max_val - min_val + 1
    return n * (min_val + max_val) // 2


if __name__ == "__main__":
    # Test case 1
    print(f"Test 1 (1, 0): {get_sum(1, 0)} (Expected: 1)")
    
    # Test case 2
    print(f"Test 2 (1, 2): {get_sum(1, 2)} (Expected: 3)")
    
    # Test case 3
    print(f"Test 3 (0, 1): {get_sum(0, 1)} (Expected: 1)")
    
    # Test case 4
    print(f"Test 4 (1, 1): {get_sum(1, 1)} (Expected: 1)")
    
    # Test case 5
    print(f"Test 5 (-1, 2): {get_sum(-1, 2)} (Expected: 2)")
