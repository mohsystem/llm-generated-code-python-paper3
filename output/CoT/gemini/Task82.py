import hashlib
import binascii

ITERATIONS = 100000
KEY_LENGTH = 32  # In bytes (256 bits)
ALGORITHM = 'sha256'

def compute_hash(password: str, salt: str) -> str:
    """
    Computes the hash of a password combined with a salt using PBKDF2.
    """
    try:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        hash_bytes = hashlib.pbkdf2_hmac(
            ALGORITHM,
            password_bytes,
            salt_bytes,
            ITERATIONS,
            dklen=KEY_LENGTH
        )
        
        return binascii.hexlify(hash_bytes).decode('ascii')
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def run_tests():
    test_cases = [
        ("password123", "somesalt1"),
        ("P@$$w0rd!", "anothersalt2"),
        ("a_very_secure_password", "salty-salt-salt"),
        ("", "emptypassword"),  # Edge case: empty password
        ("test", "")            # Edge case: empty salt
    ]

    print("Python PBKDF2-HMAC-SHA256 Hashes:")
    for password, salt in test_cases:
        hashed_password = compute_hash(password, salt)
        print(f'Password: "{password}", Salt: "{salt}"')
        print(f"Hash: {hashed_password}")
        print()

if __name__ == "__main__":
    run_tests()