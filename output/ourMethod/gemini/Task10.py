def get_sum(a: int, b: int) -> int:
    """
    Given two integers a and b, which can be positive or negative,
    find the sum of all the integers between and including them and return it.
    If the two numbers are equal return a or b.
    Note: a and b are not ordered.
    """
    if a == b:
        return a
    
    start = min(a, b)
    end = max(a, b)
    
    # Arithmetic series sum formula: n * (first + last) / 2
    # where n is the number of terms (end - start + 1)
    # Python's integers handle arbitrary size, so overflow is not an issue.
    # We use integer division //
    num_elements = end - start + 1
    return num_elements * (start + end) // 2

if __name__ == '__main__':
    # Test cases
    print(f"get_sum(1, 0) --> {get_sum(1, 0)}")       # Expected: 1
    print(f"get_sum(1, 2) --> {get_sum(1, 2)}")       # Expected: 3
    print(f"get_sum(-1, 2) --> {get_sum(-1, 2)}")     # Expected: 2
    print(f"get_sum(1, 1) --> {get_sum(1, 1)}")       # Expected: 1
    print(f"get_sum(-5, 5) --> {get_sum(-5, 5)}")     # Expected: 0