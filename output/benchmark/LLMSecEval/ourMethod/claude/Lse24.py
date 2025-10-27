
import secrets
from typing import Tuple

def generate_and_calculate_difference() -> Tuple[int, int, int]:
    """\n    Generate two random integers and calculate their difference.\n    Uses secrets module for cryptographically strong random generation.\n    """
    # Use secrets.randbelow for secure random generation
    # secrets module provides cryptographically strong random numbers
    num1 = secrets.randbelow(991) + 10  # Range [10, 1000]
    num2 = secrets.randbelow(991) + 10  # Range [10, 1000]
    
    # Calculate absolute difference to avoid negative results
    difference = abs(num1 - num2)
    
    return num1, num2, difference

def print_results(num1: int, num2: int, difference: int) -> None:
    """\n    Print results with input validation.\n    Validates range before output to prevent unexpected values.\n    """
    # Validate inputs are within expected range
    if not (10 <= num1 <= 1000) or not (10 <= num2 <= 1000):
        print("Invalid input values", file=sys.stderr)
        return
    
    # Use constant format strings to prevent injection
    print(f"First number: {num1}")
    print(f"Second number: {num2}")
    print(f"Difference: {difference}")

if __name__ == "__main__":
    import sys
    
    # Test case 1
    print("Test Case 1:")
    num1, num2, diff = generate_and_calculate_difference()
    print_results(num1, num2, diff)
    print()
    
    # Test case 2
    print("Test Case 2:")
    num1, num2, diff = generate_and_calculate_difference()
    print_results(num1, num2, diff)
    print()
    
    # Test case 3
    print("Test Case 3:")
    num1, num2, diff = generate_and_calculate_difference()
    print_results(num1, num2, diff)
    print()
    
    # Test case 4
    print("Test Case 4:")
    num1, num2, diff = generate_and_calculate_difference()
    print_results(num1, num2, diff)
    print()
    
    # Test case 5
    print("Test Case 5:")
    num1, num2, diff = generate_and_calculate_difference()
    print_results(num1, num2, diff)
