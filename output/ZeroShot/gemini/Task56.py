import secrets
import os

def generate_token(length_in_bytes: int) -> str:
    """
    Generates a secure, URL-safe random token.
    
    The 'secrets' module is used as it is the recommended way to generate
    cryptographically strong random numbers suitable for managing secrets
    such as tokens, passwords, etc.
    
    :param length_in_bytes: The number of random bytes to generate. 32 is a good default.
    :return: A URL-safe text string representing the token.
    """
    if length_in_bytes <= 0:
        return ""
    return secrets.token_urlsafe(length_in_bytes)

def main():
    """Main function with test cases."""
    print("Python: Generating 5 secure tokens (32 bytes of randomness each)")
    for i in range(5):
        token = generate_token(32)
        print(f"Test Case {i + 1}: {token}")

if __name__ == "__main__":
    main()