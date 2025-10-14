from typing import Tuple

def gcd(a: int, b: int) -> int:
    """
    Calculates the greatest common divisor (GCD) of two numbers using the iterative Euclidean algorithm.
    This function handles positive, negative, and zero inputs. The result is always non-negative.

    :param a: The first number.
    :param b: The second number.
    :return: The greatest common divisor of a and b.
    """
    # The GCD is conventionally a non-negative number.
    # gcd(a, b) = gcd(|a|, |b|).
    a = abs(a)
    b = abs(b)
    
    while b:
        a, b = b, a % b
    return a

def main():
    """
    Main function to run test cases for the gcd function.
    """
    # 5 Test Cases
    test_cases: Tuple[Tuple[int, int], ...] = (
        (54, 24),      # Standard case
        (101, 103),    # Coprime numbers
        (0, 5),        # One number is zero
        (12, 0),       # The other number is zero
        (-48, -18)     # Negative numbers
    )

    for num1, num2 in test_cases:
        result = gcd(num1, num2)
        print(f"GCD of {num1} and {num2} is: {result}")

if __name__ == "__main__":
    main()