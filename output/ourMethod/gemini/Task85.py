import secrets
import string

def generate_random_string(length: int) -> str:
    """
    Generates a cryptographically secure random string of a given length,
    consisting only of ASCII letters.

    Args:
        length: The desired length of the string. Must be non-negative.

    Returns:
        A random string of the specified length, or an empty string if length is <= 0.
    """
    if length <= 0:
        return ""
    
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")

    # Test Case 1: Length 10
    s1 = generate_random_string(10)
    print(f"Test 1 (length 10): {s1} (length: {len(s1)})")

    # Test Case 2: Length 0
    s2 = generate_random_string(0)
    print(f'Test 2 (length 0): "{s2}" (length: {len(s2)})')

    # Test Case 3: Length 1
    s3 = generate_random_string(1)
    print(f"Test 3 (length 1): {s3} (length: {len(s3)})")

    # Test Case 4: Length 32
    s4 = generate_random_string(32)
    print(f"Test 4 (length 32): {s4} (length: {len(s4)})")

    # Test Case 5: Negative length
    s5 = generate_random_string(-5)
    print(f'Test 5 (length -5): "{s5}" (length: {len(s5)})')

if __name__ == "__main__":
    main()