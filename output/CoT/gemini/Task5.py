def persistence(n):
    """
    Calculates the multiplicative persistence of a positive number.
    :param n: A positive integer.
    :return: The number of times digits must be multiplied to reach a single digit.
    """
    count = 0
    while n >= 10:
        count += 1
        product = 1
        for digit in str(n):
            product *= int(digit)
        n = product
    return count

if __name__ == '__main__':
    # Test cases
    test_cases = [39, 999, 4, 25, 679]
    expected_results = [3, 4, 0, 2, 5]

    for i in range(len(test_cases)):
        input_val = test_cases[i]
        expected = expected_results[i]
        result = persistence(input_val)
        print(f"Input: {input_val}, Output: {result}, Expected: {expected}")