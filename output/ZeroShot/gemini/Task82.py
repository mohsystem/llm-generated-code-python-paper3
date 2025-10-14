import hashlib
import os

ITERATIONS = 65536
KEY_LENGTH = 32  # bytes, equivalent to 256 bits
ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """
    Computes the hash of a password combined with a salt using PBKDF2-HMAC-SHA256.

    :param password: The password to hash (as a string).
    :param salt: The salt to use (as bytes). Must be cryptographically random.
    :return: The resulting hash as bytes.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
        
    # We need to encode the password to bytes before hashing
    password_bytes = password.encode('utf-8')
    
    # dklen is the desired key length in bytes
    return hashlib.pbkdf2_hmac(
        ALGORITHM,
        password_bytes,
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )

def main():
    """
    Main function with test cases.
    """
    passwords = [
        "password123",
        "P@$$w0rd!",
        "correct horse battery staple",
        "123",
        ""
    ]

    salts = [
        b"salt1234",
        bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        b"another-random-salt",
        b"",  # Empty salt
        b"a_very_long_salt_for_testing_purposes_with_an_empty_password"
    ]

    print("Python Password Hashing Tests:")
    for i, (password, salt) in enumerate(zip(passwords, salts)):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Password: \"{password}\"")
        print(f"Salt (hex): {salt.hex()}")
        
        hashed_password = hash_password(password, salt)
        print(f"Hashed Password (hex): {hashed_password.hex()}")

if __name__ == "__main__":
    main()