
def get_sum(a, b):
    # Handle case where a and b are equal
    if a == b:
        return a
    
    # Ensure min and max are correctly ordered
    min_val = min(a, b)
    max_val = max(a, b)
    
    # Use arithmetic series formula: sum = n * (first + last) / 2
    # where n is the count of numbers
    count = max_val - min_val + 1
    return count * (min_val + max_val) // 2

# Test cases
if __name__ == "__main__":
    print(get_sum(1, 0))    # Expected: 1
    print(get_sum(1, 2))    # Expected: 3
    print(get_sum(0, 1))    # Expected: 1
    print(get_sum(1, 1))    # Expected: 1
    print(get_sum(-1, 0))   # Expected: -1
    print(get_sum(-1, 2))   # Expected: 2
