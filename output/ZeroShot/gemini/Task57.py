def calculate_factorial(n):
    """
    Calculates the factorial of a non-negative integer securely.

    Args:
        n: The non-negative integer.

    Returns:
        The factorial of n.

    Raises:
        ValueError: If n is negative or not an integer.
    """
    # 1. Input Validation: Check for non-integer and negative inputs.
    if not isinstance(n, int) or n < 0:
        raise ValueError("Input must be a non-negative integer.")

    # 2. Python's integers have arbitrary precision, so overflow is not a concern.
    # 3. An iterative approach is used to avoid potential stack overflow with recursion.
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

# Main block with 5 test cases
if __name__ == "__main__":
    test_cases = [0, 1, 5, 20, -5]
    
    print("Python Factorial Test Cases:")
    for test in test_cases:
        try:
            factorial = calculate_factorial(test)
            print(f"Factorial of {test} is {factorial}")
        except ValueError as e:
            print(f"Error for input {test}: {e}")