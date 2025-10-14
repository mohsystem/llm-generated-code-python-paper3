import secrets
import string

def generate_random_string(length: int) -> str:
    """
    Generates a cryptographically secure random string of a specified length.
    The string consists only of ASCII letters (a-z, A-Z).

    Args:
        length: The desired length of the string. Must be non-negative.

    Returns:
        A random string of the specified length, or an empty string if length is <= 0.
    """
    if length <= 0:
        return ""
    
    # string.ascii_letters contains "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("Python Test Cases:")
    test_lengths = [16, 32, 1, 0, -5]
    for length in test_lengths:
        random_str = generate_random_string(length)
        print(f"Length {length} -> \"{random_str}\" (Actual length: {len(random_str)})")