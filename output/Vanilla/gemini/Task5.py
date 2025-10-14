def persistence(num):
    """
    Calculates the multiplicative persistence of a positive number.
    """
    count = 0
    while num >= 10:
        count += 1
        product = 1
        for digit in str(num):
            product *= int(digit)
        num = product
    return count

if __name__ == '__main__':
    # Test cases
    print(f"Input: 39, Output: {persistence(39)}")      # Expected: 3
    print(f"Input: 999, Output: {persistence(999)}")    # Expected: 4
    print(f"Input: 4, Output: {persistence(4)}")        # Expected: 0
    print(f"Input: 25, Output: {persistence(25)}")      # Expected: 2
    print(f"Input: 679, Output: {persistence(679)}")    # Expected: 5