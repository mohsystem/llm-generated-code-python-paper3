def get_sum(a, b):
    """
    Given two integers a and b, which can be positive or negative,
    find the sum of all the integers between and including them and return it.
    If the two numbers are equal return a or b.
    """
    # Use the formula for the sum of an arithmetic series:
    # sum = (number of terms / 2) * (first term + last term)
    # number of terms = abs(a - b) + 1
    # first term + last term = a + b
    # Python's integers handle arbitrary size, so no overflow issues.
    # The // operator performs integer division.
    return (a + b) * (abs(a - b) + 1) // 2

if __name__ == '__main__':
    # Test cases
    print(get_sum(1, 0))    # Expected: 1
    print(get_sum(1, 2))    # Expected: 3
    print(get_sum(1, 1))    # Expected: 1
    print(get_sum(-1, 0))   # Expected: -1
    print(get_sum(-1, 2))   # Expected: 2