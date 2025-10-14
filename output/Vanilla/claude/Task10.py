
def get_sum(a, b):
    if a == b:
        return a
    
    min_val = min(a, b)
    max_val = max(a, b)
    
    # Sum formula: n * (first + last) / 2
    count = max_val - min_val + 1
    return count * (min_val + max_val) // 2

if __name__ == "__main__":
    print(get_sum(1, 0))    # Expected: 1
    print(get_sum(1, 2))    # Expected: 3
    print(get_sum(0, 1))    # Expected: 1
    print(get_sum(1, 1))    # Expected: 1
    print(get_sum(-1, 0))   # Expected: -1
    print(get_sum(-1, 2))   # Expected: 2
