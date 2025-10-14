def get_sum(a: int, b: int) -> int:
    """
    Calculates the sum of all integers between and including two given integers.
    Uses a mathematical formula for an arithmetic series to efficiently compute the sum.
    Python's arbitrary-precision integers handle potential overflow automatically.
    
    :param a: The first integer.
    :param b: The second integer.
    :return: The sum of all integers between a and b, inclusive.
    """
    if a == b:
        return a
    
    min_val = min(a, b)
    max_val = max(a, b)
    
    # Formula for the sum of an arithmetic series: n * (first + last) / 2
    # where n is the number of terms (max - min + 1).
    # Use integer division //.
    return (max_val - min_val + 1) * (min_val + max_val) // 2

if __name__ == '__main__':
    # Test Cases
    print(get_sum(1, 0))    # Expected output: 1
    print(get_sum(1, 2))    # Expected output: 3
    print(get_sum(0, 1))    # Expected output: 1
    print(get_sum(1, 1))    # Expected output: 1
    print(get_sum(-1, 2))   # Expected output: 2