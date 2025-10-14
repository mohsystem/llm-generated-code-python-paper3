import sys
from typing import Union

def divide(numerator: int, denominator: int) -> float:
    """
    Divides two integers.
    Args:
        numerator: The number to be divided.
        denominator: The number to divide by.
    Returns:
        The result of the division as a float.
    Raises:
        ValueError: If the denominator is zero.
    """
    if denominator == 0:
        # Rule #6: Handle potential runtime errors
        raise ValueError("Error: Division by zero is not allowed.")
    return float(numerator) / denominator

def process_division(num_str1: str, num_str2: str) -> None:
    """
    Processes two string inputs, converts to integers, performs division,
    and prints the result or an error message.
    """
    print(f'Processing inputs: "{num_str1}", "{num_str2}"')
    try:
        # Rule #1: Validate input by converting to the expected type.
        # Rule #7: Use safe parsing (int() conversion).
        numerator = int(num_str1)
        denominator = int(num_str2)
        
        result = divide(numerator, denominator)
        print(f"Result: {result}")
    # Rule #6: Ensure all exceptions are caught and handled.
    except ValueError as e:
        # Catches both int() conversion errors and our division-by-zero error.
        print(f"Error: {e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        print("--- Operation finished ---")

def main():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")
    
    # Test Case 1: Valid input
    process_division("10", "2")
    
    # Test Case 2: Division by zero
    process_division("5", "0")
    
    # Test Case 3: Non-numeric input for numerator
    process_division("abc", "5")
    
    # Test Case 4: Non-numeric input for denominator
    process_division("10", "xyz")
    
    # Test Case 5: Floating point input
    process_division("12.5", "2")

if __name__ == "__main__":
    main()