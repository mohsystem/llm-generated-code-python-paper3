
from typing import Optional

def factorial(n: int) -> int:
    """\n    Calculates the factorial of a non-negative integer.\n    \n    Args:\n        n: The number to calculate factorial for\n        \n    Returns:\n        The factorial as an integer\n        \n    Raises:\n        ValueError: If n is negative or exceeds safe limit\n        TypeError: If n is not an integer\n    """
    if not isinstance(n, int):
        raise TypeError("Input must be an integer")
    
    if n < 0:
        raise ValueError("Input must be non-negative")
    
    if n > 100000:
        raise ValueError("Input too large (max 100000)")
    
    result = 1
    for i in range(2, n + 1):
        result *= i
    
    return result


def main() -> None:
    """Test cases for factorial function."""
    
    # Test case 1: 0! = 1
    try:
        print(f"0! = {factorial(0)}")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
    
    # Test case 2: 5! = 120
    try:
        print(f"5! = {factorial(5)}")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
    
    # Test case 3: 10! = 3628800
    try:
        print(f"10! = {factorial(10)}")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
    
    # Test case 4: 20! = 2432902008176640000
    try:
        print(f"20! = {factorial(20)}")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
    
    # Test case 5: Negative number (should raise exception)
    try:
        print(f"-5! = {factorial(-5)}")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
