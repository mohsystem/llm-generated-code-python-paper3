import math

def factorial(n: int) -> int:
    """
    Calculates the factorial of a non-negative integer.

    Args:
        n: The non-negative integer.

    Returns:
        The factorial of n.

    Raises:
        ValueError: if n is negative.
    """
    # Rule #4: Validate input to ensure it's a non-negative integer.
    if not isinstance(n, int) or n < 0:
        raise ValueError("Input must be a non-negative integer.")
    
    # Python integers support arbitrary precision, so overflow is not a concern
    # for the data type itself, unlike in fixed-size integer languages.
    # We can use math.factorial for a safe and optimized implementation.
    return math.factorial(n)

if __name__ == '__main__':
    # Using 6 test cases to cover different scenarios, including errors.
    test_cases = [0, 1, 5, 10, -1, 15.5]

    print("Running test cases for factorial calculation:")
    for test_value in test_cases:
        print("-------------------------------------")
        print(f"Calculating factorial for: {test_value}")
        try:
            # Rule #8: Ensure all exceptions are caught and handled.
            result = factorial(test_value)
            print(f"Result: {result}")
        except ValueError as e:
            print(f"Error: {e}", file=__import__('sys').stderr)
    print("-------------------------------------")