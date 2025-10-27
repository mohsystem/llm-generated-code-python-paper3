import secrets
import sys

def generate_randoms_and_difference(min_val: int, max_val: int) -> str:
    """
    Generates two cryptographically secure random integers within a specified range,
    calculates their absolute difference, and returns the result as a formatted string.

    Args:
        min_val: The minimum value of the range (inclusive).
        max_val: The maximum value of the range (inclusive).

    Returns:
        A string describing the two numbers and their difference.
    
    Raises:
        ValueError: If min_val is greater than max_val.
        Exception: If the underlying OS entropy source is unavailable.
    """
    if min_val > max_val:
        raise ValueError("Min value cannot be greater than Max value.")
    
    range_size = max_val - min_val + 1
    
    # secrets.randbelow(n) returns a random int in [0, n).
    try:
        num1 = secrets.randbelow(range_size) + min_val
        num2 = secrets.randbelow(range_size) + min_val
    except Exception as e:
        # secrets module can fail if it cannot find an OS-level source of entropy.
        sys.stderr.write(f"Error: Could not generate secure random numbers. Reason: {e}\n")
        raise
        
    difference = abs(num1 - num2)
    
    return f"Num1: {num1}, Num2: {num2}, Difference: {difference}"

def main():
    """Main function to run test cases."""
    print("Running 5 test cases...")
    min_val = 10
    max_val = 1000

    for i in range(5):
        try:
            result = generate_randoms_and_difference(min_val, max_val)
            print(f"Test Case {i + 1}: {result}")
        except (ValueError, Exception) as e:
            print(f"Test Case {i + 1}: Failed - {e}", file=sys.stderr)

if __name__ == "__main__":
    main()