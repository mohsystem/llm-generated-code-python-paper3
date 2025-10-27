import hashlib
import os

# Hashing parameters
SALT_LENGTH = 16  # 16 bytes salt
ITERATIONS = 65536
KEY_LENGTH = 32  # 32 bytes for SHA-256
HASH_ALGORITHM = 'sha256'

def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """
    Generates a cryptographically secure random salt.

    :param length: The desired length of the salt in bytes.
    :return: A byte string containing the salt.
    """
    return os.urandom(length)

def hash_password(password: str, salt: bytes) -> bytes:
    """
    Hashes the password using PBKDF2 algorithm.

    :param password: The password to hash.
    :param salt: The salt to use for hashing.
    :return: The hashed password as a byte string.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
        
    # We use PBKDF2 with HMAC-SHA256.
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    return key

def register_user(username: str, password: str) -> str:
    """
    Simulates user registration by generating a salt, hashing the password,
    and concatenating them for storage.

    :param username: The username (not used in hashing but part of a typical registration).
    :param password: The plain-text password.
    :return: A string representing the salt and hashed password, ready for storage.
    """
    # 1. Generate a salt
    salt = generate_salt()

    # 2. Hash the password with the salt
    hashed_password = hash_password(password, salt)

    # 3. Concatenate salt and hash (in hex format for easy string storage)
    # A separator is used to easily split the salt and hash later during verification.
    return f"{salt.hex()}:{hashed_password.hex()}"

class Lse96:
    @staticmethod
    def main():
        """Main function to run test cases."""
        print("--- Running Python Registration Test Cases ---")

        # Test Case 1
        stored_credentials1 = register_user("user1", "Password123!")
        print(f"User: user1, Stored: {stored_credentials1}")

        # Test Case 2
        stored_credentials2 = register_user("admin_test", "S3cureP@ssw0rd")
        print(f"User: admin_test, Stored: {stored_credentials2}")

        # Test Case 3
        stored_credentials3 = register_user("jane.doe", "another-password-4-jane")
        print(f"User: jane.doe, Stored: {stored_credentials3}")

        # Test Case 4: Simple password
        stored_credentials4 = register_user("test_user", "password")
        print(f"User: test_user, Stored: {stored_credentials4}")

        # Test Case 5: Long password with many special characters
        stored_credentials5 = register_user("poweruser", "L0ngP@$$w0rd_With_Many_Ch@r$!#%^&*()")
        print(f"User: poweruser, Stored: {stored_credentials5}")

if __name__ == "__main__":
    Lse96.main()