import secrets
import sys

def generate_random_int(min_val: int, max_val: int) -> int:
    """
    Generates a cryptographically secure random integer within a specified range.

    Args:
        min_val: The minimum value of the range (inclusive).
        max_val: The maximum value of the range (inclusive).

    Returns:
        A random integer within the specified range.

    Raises:
        ValueError: if min_val is greater than or equal to max_val.
    """
    if min_val >= max_val:
        raise ValueError("Max must be greater than min.")
    
    # secrets.randbelow(n) returns a random int in [0, n).
    # To get a value in [min_val, max_val], we need a range of size (max_val - min_val + 1).
    return secrets.randbelow(max_val - min_val + 1) + min_val

def generate_random_token_hex(num_bytes: int) -> str:
    """
    Generates a cryptographically secure random token as a hexadecimal string.

    Args:
        num_bytes: The number of random bytes to generate. 
                   The resulting hex string will be 2 * num_bytes long.

    Returns:
        A random token encoded as a hexadecimal string.

    Raises:
        ValueError: if num_bytes is not positive.
    """
    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive.")
    return secrets.token_hex(num_bytes)

def main():
    """Main function with test cases."""
    print("--- Testing Random Number and Token Generation ---")

    # Test Case 1: Standard integer range
    print("Test Case 1: Random int between 1 and 100")
    random_int1 = generate_random_int(1, 100)
    print(f"Generated Number: {random_int1}\n")

    # Test Case 2: Negative integer range
    print("Test Case 2: Random int between -50 and -10")
    random_int2 = generate_random_int(-50, -10)
    print(f"Generated Number: {random_int2}\n")

    # Test Case 3: 16-byte (128-bit) random token
    print("Test Case 3: 16-byte random token (32 hex characters)")
    token1 = generate_random_token_hex(16)
    print(f"Generated Token: {token1}\n")

    # Test Case 4: 32-byte (256-bit) random token
    print("Test Case 4: 32-byte random token (64 hex characters)")
    token2 = generate_random_token_hex(32)
    print(f"Generated Token: {token2}\n")
    
    # Test Case 5: Invalid range for integer generation
    print("Test Case 5: Invalid range (100, 1)")
    try:
        generate_random_int(100, 1)
    except ValueError as e:
        print(f"Caught expected exception: {e}")

if __name__ == "__main__":
    main()