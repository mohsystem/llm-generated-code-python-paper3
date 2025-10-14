
def calculate_factorial(n):
    """\n    Calculate the factorial of a number with security validations.\n    \n    Args:\n        n: Integer input for factorial calculation\n        \n    Returns:\n        Factorial of n as an integer\n        \n    Raises:\n        ValueError: If input is negative or too large\n        TypeError: If input is not an integer\n    """
    # Type validation
    if not isinstance(n, int):
        raise TypeError("Input must be an integer")
    
    # Input validation to prevent negative numbers
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    
    # Check for reasonable upper limit to prevent resource exhaustion
    if n > 10000:
        raise ValueError("Input too large - maximum value is 10000")
    
    # Base cases
    if n == 0 or n == 1:
        return 1
    
    # Calculate factorial iteratively (safer than recursion for large numbers)
    result = 1
    for i in range(2, n + 1):
        result *= i
    
    return result


def main():
    """Main function with test cases"""
    print("Test Case 1: Factorial of 0 =", calculate_factorial(0))
    print("Test Case 2: Factorial of 1 =", calculate_factorial(1))
    print("Test Case 3: Factorial of 5 =", calculate_factorial(5))
    print("Test Case 4: Factorial of 10 =", calculate_factorial(10))
    print("Test Case 5: Factorial of 20 =", calculate_factorial(20))
    
    # Test error handling
    try:
        print("Test Case 6 (Error): Factorial of -5")
        calculate_factorial(-5)
    except ValueError as e:
        print("Error:", str(e))


if __name__ == "__main__":
    main()
