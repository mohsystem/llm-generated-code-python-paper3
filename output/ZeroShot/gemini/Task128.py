import secrets
import string

def generate_secure_random_number(min_val, max_val):
    """
    Generates a cryptographically secure random integer in a given range [min_val, max_val].
    """
    if min_val > max_val:
        raise ValueError("min_val must not be greater than max_val")
    # secrets.randbelow(n) returns a random int in [0, n).
    # To get a range of [min_val, max_val], we need a range of size (max_val - min_val + 1)
    range_size = max_val - min_val + 1
    return min_val + secrets.randbelow(range_size)

def generate_secure_token(length):
    """
    Generates a cryptographically secure alphanumeric token of a given length.
    """
    if length <= 0:
        raise ValueError("Token length must be positive.")
    alphabet = string.ascii_letters + string.digits
    # secrets.choice is suitable for generating single random elements from a sequence.
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    """Main function with test cases."""
    print("--- Secure Random Number Generation ---")
    for i in range(5):
        min_val = i * 10
        max_val = 50 + i * 10
        try:
            random_number = generate_secure_random_number(min_val, max_val)
            print(f"Test {i+1}: Random number between {min_val} and {max_val}: {random_number}")
        except ValueError as e:
            print(f"Error: {e}")

    print("\n--- Secure Random Token Generation ---")
    for i in range(5):
        length = 8 + i * 4
        try:
            token = generate_secure_token(length)
            print(f"Test {i+1}: Token of length {length}: {token}")
        except ValueError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()