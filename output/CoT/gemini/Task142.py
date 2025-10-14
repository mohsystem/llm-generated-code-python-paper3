def find_gcd(a, b):
    """
    Finds the greatest common divisor (GCD) of two integers using the Euclidean algorithm.

    :param a: The first integer.
    :param b: The second integer.
    :return: The greatest common divisor of a and b.
    """
    # The Euclidean algorithm
    while b:
        a, b = b, a % b
    # The GCD is conventionally a non-negative number.
    return abs(a)

if __name__ == "__main__":
    # 5 Test Cases
    test_cases = [
        (54, 24),     # Basic case with two positive numbers
        (100, 0),     # Case with zero
        (-48, 18),    # Case with a negative number
        (17, 23),     # Case with two prime numbers
        (0, 0)        # Case where both numbers are zero
    ]

    for num1, num2 in test_cases:
        result = find_gcd(num1, num2)
        print(f"The GCD of {num1} and {num2} is: {result}")