import secrets
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

ITERATIONS = 600_000
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_LENGTH = 16  # 16 bytes = 128 bits

def generate_salt() -> bytes:
    """
    Generates a cryptographically secure random salt.

    Returns:
        A 16-byte salt.
    """
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password: Union[str, bytes], salt: bytes) -> str:
    """
    Computes the hash of a password combined with a salt using PBKDF2 with HMAC-SHA256.

    Args:
        password: The password to hash, as a string or bytes.
        salt: The salt to use.

    Returns:
        The resulting hash as a hex-encoded string.
    """
    if not password or not salt:
        raise ValueError("Password and salt must not be empty.")

    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    return key.hex()

def main():
    """Main function with test cases."""
    test_passwords = [
        "P@ssword123!",
        "correct horse battery staple",
        "Tr0ub4dor&3",
        "123456",
        "super-secret-password"
    ]

    print("Running 5 test cases for password hashing...")
    for password in test_passwords:
        try:
            # In a real application, never log or print the plaintext password.
            # This is for demonstration purposes only.
            print("\n--- Test Case ---")
            print(f"Password (for demo only): {password}")

            salt = generate_salt()
            print(f"Generated Salt (hex): {salt.hex()}")

            hashed_password = hash_password(password, salt)
            print(f"Hashed Password (hex): {hashed_password}")

        except ValueError as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()