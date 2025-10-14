def get_sum(a, b):
    """
    Given two integers a and b, which can be positive or negative,
    find the sum of all the integers between and including them and return it.
    If the two numbers are equal return a or b.
    """
    # If the numbers are the same, return one of them.
    if a == b:
        return a
    
    # Determine the minimum and maximum of the two numbers.
    first = min(a, b)
    last = max(a, b)
    
    # Apply the formula for the sum of an arithmetic series:
    # Sum = n/2 * (first + last)
    # where n is the number of terms (last - first + 1)
    # Python's integers handle arbitrary size, so overflow is not an issue.
    return (last - first + 1) * (first + last) // 2

if __name__ == '__main__':
    # Test cases
    print(get_sum(1, 0))    # Expected: 1
    print(get_sum(1, 2))    # Expected: 3
    print(get_sum(1, 1))    # Expected: 1
    print(get_sum(-1, 0))   # Expected: -1
    print(get_sum(-1, 2))   # Expected: 2