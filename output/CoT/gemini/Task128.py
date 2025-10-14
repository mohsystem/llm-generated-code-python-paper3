import secrets
import string

def generate_random_int(min_val: int, max_val: int) -> int:
    """
    Generates a cryptographically secure random integer within a specified range.
    :param min_val: The minimum value (inclusive).
    :param max_val: The maximum value (inclusive).
    :return: A random integer between min_val and max_val.
    """
    if min_val >= max_val:
        raise ValueError("max_val must be greater than min_val")
    
    # secrets.randbelow(n) returns a random integer in the range [0, n-1].
    range_size = max_val - min_val + 1
    return secrets.randbelow(range_size) + min_val

def generate_random_token(length: int) -> str:
    """
    Generates a cryptographically secure random alphanumeric token of a specified length.
    :param length: The desired length of the token.
    :return: A random alphanumeric token.
    """
    if length <= 0:
        raise ValueError("Token length must be positive.")
    
    # Define the character set to use for the token
    alphabet = string.ascii_letters + string.digits
    
    # Generate the token by choosing characters from the alphabet
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("Python Random Generation Test Cases:")

    # Test Case 1
    print(f"1. Random integer between 1 and 100: {generate_random_int(1, 100)}")

    # Test Case 2
    print(f"2. Random integer between -50 and 50: {generate_random_int(-50, 50)}")

    # Test Case 3
    print(f"3. Random token of length 8: {generate_random_token(8)}")

    # Test Case 4
    print(f"4. Random token of length 16: {generate_random_token(16)}")

    # Test Case 5
    print(f"5. Random integer between 1000 and 5000: {generate_random_int(1000, 5000)}")