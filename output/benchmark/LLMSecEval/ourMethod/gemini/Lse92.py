import hashlib
import secrets
import base64
import sys

ITERATIONS = 210000
SALT_SIZE = 16  # bytes
KEY_LENGTH = 32  # bytes, equivalent to 256 bits

def register_user(username: str, password: str) -> str:
    """
    Hashes a password using PBKDF2 with HMAC-SHA256.

    Args:
        username: The username (for context, not used in hash).
        password: The password to hash.

    Returns:
        A string containing the salt and hash, encoded in Base64 and separated by a colon.
    """
    # Rule #7: Use a strong, cryptographically secure random number generator to create salts.
    # The `secrets` module is preferred for this purpose.
    salt = secrets.token_bytes(SALT_SIZE)

    # Rule #5: Use PBKDF2-HMAC-SHA-256 with a high iteration count.
    # `hashlib.pbkdf2_hmac` is part of the standard library.
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )

    # Encode salt and hash to Base64 to create a storable string.
    # Rule #6: Store the salt with the hash.
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(hash_bytes).decode('ascii')

    return f"{salt_b64}:{hash_b64}"

def main():
    """Main function with test cases."""
    print("Running registration simulation...")

    test_users = [
        ("alice", "Password123!"),
        ("bob", "my$ecretP@ssw0rd"),
        ("charlie", "an0th3r_sTr0ng_p@ss"),
        ("david", "w3ak"),
        ("eve", "Eve's_Password_is_very_long_and_secure_hopefully")
    ]

    for username, password in test_users:
        try:
            hashed_password = register_user(username, password)
            print(f"Username: {username}")
            print("Password: [REDACTED]")
            print(f"Stored Hash: {hashed_password}")
            print("---")
        except Exception as e:
            print(f"Failed to register user {username}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()