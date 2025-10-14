
from typing import Union


def gcd(a: int, b: int) -> int:
    """\n    Computes the greatest common divisor of two numbers using Euclidean algorithm.\n    \n    Args:\n        a: First number\n        b: Second number\n        \n    Returns:\n        GCD of a and b\n        \n    Raises:\n        ValueError: If either number is negative or both are zero\n        TypeError: If inputs are not integers\n    """
    # Validate input types
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Both inputs must be integers")
    
    # Validate inputs - only non-negative numbers allowed
    if a < 0 or b < 0:
        raise ValueError("Both numbers must be non-negative")
    
    # Handle edge case where both are zero
    if a == 0 and b == 0:
        raise ValueError("GCD of 0 and 0 is undefined")
    
    # Euclidean algorithm
    while b != 0:
        a, b = b, a % b
    return a


def main() -> None:
    """Main function with test cases and user input."""
    # Test cases
    print("Test Case 1: GCD(48, 18) =", gcd(48, 18))
    print("Test Case 2: GCD(100, 50) =", gcd(100, 50))
    print("Test Case 3: GCD(17, 19) =", gcd(17, 19))
    print("Test Case 4: GCD(0, 5) =", gcd(0, 5))
    print("Test Case 5: GCD(1071, 462) =", gcd(1071, 462))
    
    # Interactive input with validation
    print("\\nEnter two non-negative integers:")
    try:
        num1_input = input("First number: ").strip()
        num2_input = input("Second number: ").strip()
        
        # Validate input format
        if not num1_input or not num2_input:
            print("Error: Input cannot be empty", file=__import__('sys').stderr)
            return
        
        # Parse and validate integers
        try:
            num1 = int(num1_input)
            num2 = int(num2_input)
        except ValueError:
            print("Error: Invalid input. Please enter valid integers.", 
                  file=__import__('sys').stderr)
            return
        
        result = gcd(num1, num2)
        print(f"GCD({num1}, {num2}) = {result}")
        
    except ValueError as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    except TypeError as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    except Exception as e:
        print("Error: An unexpected error occurred.", file=__import__('sys').stderr)


if __name__ == "__main__":
    main()
