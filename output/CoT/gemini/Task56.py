import secrets
import os

def generate_token(byte_length: int) -> str:
    """
    Generates a cryptographically secure, URL-safe token.

    Args:
        byte_length: The number of random bytes to generate. 32 is recommended.

    Returns:
        A URL-safe text string, containing byte_length*1.3~ random characters.
    """
    if not isinstance(byte_length, int) or byte_length <= 0:
        raise ValueError("Byte length must be a positive integer.")
    # secrets.token_urlsafe is designed for this purpose.
    # It generates random bytes and Base64 encodes them to be URL-safe.
    return secrets.token_urlsafe(byte_length)

def main():
    """Main function with test cases."""
    print("Python Token Generation Test Cases:")
    
    # Test Case 1: 16 bytes (128 bits)
    print(f"1. 16-byte token: {generate_token(16)}")
    
    # Test Case 2: 32 bytes (256 bits) - Recommended
    print(f"2. 32-byte token: {generate_token(32)}")
    
    # Test Case 3: 48 bytes (384 bits)
    print(f"3. 48-byte token: {generate_token(48)}")
    
    # Test Case 4: Another 32-byte token to show it's different
    print(f"4. 32-byte token: {generate_token(32)}")
    
    # Test Case 5: 64 bytes (512 bits)
    print(f"5. 64-byte token: {generate_token(64)}")

if __name__ == "__main__":
    main()