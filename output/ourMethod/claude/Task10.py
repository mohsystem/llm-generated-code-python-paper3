
def get_sum(a: int, b: int) -> int:
    if a == b:
        return a
    
    min_val = min(a, b)
    max_val = max(a, b)
    
    n = max_val - min_val + 1
    total = n * (min_val + max_val) // 2
    
    return total


if __name__ == "__main__":
    print(get_sum(1, 0))
    print(get_sum(1, 2))
    print(get_sum(0, 1))
    print(get_sum(1, 1))
    print(get_sum(-1, 0))
    print(get_sum(-1, 2))
