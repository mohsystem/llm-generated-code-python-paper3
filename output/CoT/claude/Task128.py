
import secrets
import string

def generate_secure_random_int(min_val, max_val):
    """\n    Generates a cryptographically secure random integer within a range\n    :param min_val: Minimum value (inclusive)\n    :param max_val: Maximum value (inclusive)\n    :return: Random integer between min_val and max_val\n    """
    if min_val > max_val:
        raise ValueError("min_val must be less than or equal to max_val")
    return secrets.randbelow(max_val - min_val + 1) + min_val


def generate_secure_token(byte_length):
    """\n    Generates a cryptographically secure random token (URL-safe)\n    :param byte_length: Length of random bytes\n    :return: URL-safe random token\n    """
    if byte_length <= 0:
        raise ValueError("byte_length must be positive")
    return secrets.token_urlsafe(byte_length)


def generate_alphanumeric_token(length):
    """\n    Generates a cryptographically secure alphanumeric token\n    :param length: Length of the token\n    :return: Alphanumeric random token\n    """
    if length <= 0:
        raise ValueError("length must be positive")
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_hex_token(byte_length):
    """\n    Generates a cryptographically secure hexadecimal token\n    :param byte_length: Length of random bytes\n    :return: Hexadecimal random token\n    """
    if byte_length <= 0:
        raise ValueError("byte_length must be positive")
    return secrets.token_hex(byte_length)


def generate_secure_random_bytes(byte_length):
    """\n    Generates cryptographically secure random bytes\n    :param byte_length: Number of bytes to generate\n    :return: Random bytes\n    """
    if byte_length <= 0:
        raise ValueError("byte_length must be positive")
    return secrets.token_bytes(byte_length)


if __name__ == "__main__":
    print("=== Cryptographically Secure Random Number/Token Generator ===\\n")
    
    # Test Case 1: Random integer in range
    print("Test Case 1: Random integer between 1 and 100")
    print(f"Result: {generate_secure_random_int(1, 100)}")
    print()
    
    # Test Case 2: URL-safe token (32 bytes)
    print("Test Case 2: URL-safe token (32 bytes)")
    print(f"Result: {generate_secure_token(32)}")
    print()
    
    # Test Case 3: Alphanumeric token (16 characters)
    print("Test Case 3: Alphanumeric token (16 chars)")
    print(f"Result: {generate_alphanumeric_token(16)}")
    print()
    
    # Test Case 4: Hexadecimal token (16 bytes)
    print("Test Case 4: Hexadecimal token (16 bytes)")
    print(f"Result: {generate_hex_token(16)}")
    print()
    
    # Test Case 5: Random bytes (32 bytes)
    print("Test Case 5: Random bytes (32 bytes)")
    random_bytes = generate_secure_random_bytes(32)
    print(f"Result: {random_bytes.hex()}")
    print()
