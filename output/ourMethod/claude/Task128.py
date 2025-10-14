
import secrets
from typing import Union

def generate_random_number(min_val: int, max_val: int) -> int:
    """\n    Generates a cryptographically secure random integer within the specified range.\n    \n    Args:\n        min_val: Minimum value (inclusive)\n        max_val: Maximum value (inclusive)\n        \n    Returns:\n        Random integer between min_val and max_val\n    """
    if not isinstance(min_val, int) or not isinstance(max_val, int):
        raise TypeError("min_val and max_val must be integers")
    
    if min_val > max_val:
        raise ValueError("min_val must be less than or equal to max_val")
    
    if min_val == max_val:
        return min_val
    
    return secrets.randbelow(max_val - min_val + 1) + min_val


def generate_random_token(length: int) -> str:
    """\n    Generates a cryptographically secure random token.\n    \n    Args:\n        length: Length of the token in bytes\n        \n    Returns:\n        URL-safe Base64-encoded random token\n    """
    if not isinstance(length, int) or length <= 0 or length > 1024:
        raise ValueError("Length must be an integer between 1 and 1024 bytes")
    
    return secrets.token_urlsafe(length)


def generate_random_hex_token(length: int) -> str:
    """\n    Generates a cryptographically secure random hexadecimal token.\n    \n    Args:\n        length: Length of the token in bytes\n        \n    Returns:\n        Hexadecimal string representation of random bytes\n    """
    if not isinstance(length, int) or length <= 0 or length > 1024:
        raise ValueError("Length must be an integer between 1 and 1024 bytes")
    
    return secrets.token_hex(length)


def generate_random_bytes(length: int) -> bytes:
    """\n    Generates cryptographically secure random bytes.\n    \n    Args:\n        length: Number of random bytes to generate\n        \n    Returns:\n        Random bytes\n    """
    if not isinstance(length, int) or length <= 0 or length > 1024:
        raise ValueError("Length must be an integer between 1 and 1024 bytes")
    
    return secrets.token_bytes(length)


def main() -> None:
    # Test case 1: Generate random number in range 1-100
    print(f"Test 1 - Random number (1-100): {generate_random_number(1, 100)}")
    
    # Test case 2: Generate random number in range 0-1000
    print(f"Test 2 - Random number (0-1000): {generate_random_number(0, 1000)}")
    
    # Test case 3: Generate 16-byte Base64 token
    print(f"Test 3 - 16-byte Base64 token: {generate_random_token(16)}")
    
    # Test case 4: Generate 32-byte Base64 token
    print(f"Test 4 - 32-byte Base64 token: {generate_random_token(32)}")
    
    # Test case 5: Generate 16-byte hexadecimal token
    print(f"Test 5 - 16-byte hex token: {generate_random_hex_token(16)}")


if __name__ == "__main__":
    main()
