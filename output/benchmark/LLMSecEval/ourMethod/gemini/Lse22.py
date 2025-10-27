import secrets
import sys

def generate_random_number():
    """
    Generates a cryptographically secure random number greater than 1000.
    
    Returns:
        int: A random integer greater than 1000.
    """
    # The number must be > 1000, so the minimum value is 1001.
    min_val = 1001
    
    # We use a large but reasonable upper bound to avoid excessively large numbers.
    # For example, up to 1,000,000.
    max_val = 1000000
    
    # secrets.randbelow(n) returns a random integer in the range [0, n).
    # To get a number in the range [min_val, max_val], we generate a number
    # in a range of size (max_val - min_val + 1) and add min_val to it.
    if min_val > max_val:
        raise ValueError("min_val cannot be greater than max_val")
        
    range_size = max_val - min_val + 1
    
    return min_val + secrets.randbelow(range_size)

def main():
    """Main function to run test cases."""
    print("Generating 5 random numbers greater than 1000:")
    for i in range(5):
        try:
            random_num = generate_random_number()
            print(f"Test Case {i + 1}: {random_num}")
        except ValueError as e:
            print(f"Error generating number: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()