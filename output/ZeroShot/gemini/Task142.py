def gcd(a, b):
    """
    Calculates the greatest common divisor (GCD) of two numbers using the iterative Euclidean algorithm.
    This function is secure against recursion depth limits by being iterative and handles edge cases
    such as zero and negative inputs by taking their absolute values.

    :param a: The first number.
    :param b: The second number.
    :return: The greatest common divisor of a and b.
    """
    # The GCD is conventionally defined for positive integers.
    # gcd(a, b) is equal to gcd(|a|, |b|).
    a = abs(a)
    b = abs(b)

    # Iterative Euclidean algorithm using tuple swapping
    while b:
        a, b = b, a % b
    
    # The algorithm naturally handles cases like gcd(n, 0) = n and gcd(0, 0) = 0.
    return a

if __name__ == "__main__":
    print("Running test cases for Python GCD:")

    # Test Case 1: Standard case
    a1, b1 = 48, 18
    print(f"GCD({a1}, {b1}) = {gcd(a1, b1)}")

    # Test Case 2: Coprime numbers (GCD is 1)
    a2, b2 = 101, 103
    print(f"GCD({a2}, {b2}) = {gcd(a2, b2)}")

    # Test Case 3: One number is zero
    a3, b3 = 56, 0
    print(f"GCD({a3}, {b3}) = {gcd(a3, b3)}")

    # Test Case 4: Negative inputs
    a4, b4 = -60, 48
    print(f"GCD({a4}, {b4}) = {gcd(a4, b4)}")

    # Test Case 5: Both numbers are zero
    a5, b5 = 0, 0
    print(f"GCD({a5}, {b5}) = {gcd(a5, b5)}")