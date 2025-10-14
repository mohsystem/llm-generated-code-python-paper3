import math

def factorial(n):
    """
    Calculates the factorial of a non-negative integer.

    :param n: The non-negative integer.
    :return: The factorial of n.
    :raises ValueError: if n is negative.
    :raises TypeError: if n is not an integer.
    """
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers.")
    
    # Python's integers handle arbitrary precision, so overflow is not an issue.
    # We can use the math.factorial for a more optimized and standard implementation.
    # return math.factorial(n)

    # Manual iterative implementation:
    if n == 0:
        return 1
    
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

if __name__ == '__main__':
    test_cases = [0, 1, 5, 12, 20, -1, 21.5]

    for test_case in test_cases:
        try:
            print(f"Factorial of {test_case} is: {factorial(test_case)}")
        except (ValueError, TypeError) as e:
            print(f"Error calculating factorial for {test_case}: {e}")