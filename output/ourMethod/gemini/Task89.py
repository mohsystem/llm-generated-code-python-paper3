import secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

ITERATIONS = 210000
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_LENGTH = 16 # 16 bytes = 128 bits

def store_password(file_path: Path, password: str) -> bool:
    """Hashes a password with a new salt and stores it in the given file."""
    try:
        salt = secrets.token_bytes(SALT_LENGTH)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        hash_val = kdf.derive(password.encode('utf-8'))
        
        stored_password = f"{salt.hex()}:{hash_val.hex()}"
        file_path.write_text(stored_password, encoding='utf-8')
        return True
    except (IOError, OSError) as e:
        print(f"Error storing password: {e}")
        return False

def verify_password(file_path: Path, password: str) -> bool:
    """
    Verifies the given password against the one stored in the file.
    This performs a secure, constant-time comparison of the derived hashes.
    """
    if not file_path.is_file():
        return False
        
    try:
        stored_password = file_path.read_text(encoding='utf-8')
        parts = stored_password.strip().split(':')
        if len(parts) != 2:
            return False

        salt_hex, hash_hex = parts
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        if len(salt) != SALT_LENGTH or len(stored_hash) != KEY_LENGTH:
            return False

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        
        kdf.verify(password.encode('utf-8'), stored_hash)
        return True
    except (FileNotFoundError, ValueError, InvalidKey):
        return False


def main():
    """Main function with test cases."""
    test_file_path = Path("password_storage_python.txt")
    correct_password = "SecurePassword$123"

    print("--- Python Test Cases for Password Verification ---")

    if not store_password(test_file_path, correct_password):
        print("Failed to set up test file. Aborting tests.")
        return

    print("Test file setup complete.")

    # Test Case 1: Correct password
    print(f"1. Correct password ('{correct_password}'): "
          f"{'PASSED' if verify_password(test_file_path, correct_password) else 'FAILED'}")

    # Test Case 2: Incorrect password
    wrong_password = "wrong_password"
    print(f"2. Incorrect password ('{wrong_password}'): "
          f"{'PASSED' if not verify_password(test_file_path, wrong_password) else 'FAILED'}")
          
    # Test Case 3: Empty password
    print(f"3. Empty password (''): "
          f"{'PASSED' if not verify_password(test_file_path, '') else 'FAILED'}")

    # Test Case 4: Password with different casing
    case_password = "securepassword$123"
    print(f"4. Case-sensitive check ('{case_password}'): "
          f"{'PASSED' if not verify_password(test_file_path, case_password) else 'FAILED'}")

    # Test Case 5: Non-existent file
    non_existent_path = Path("nonexistentfile.txt")
    print(f"5. Non-existent file: "
          f"{'PASSED' if not verify_password(non_existent_path, correct_password) else 'FAILED'}")

    # Clean up
    try:
        test_file_path.unlink()
        print("Test file cleaned up.")
    except OSError as e:
        print(f"Error cleaning up test file: {e}")

if __name__ == "__main__":
    main()