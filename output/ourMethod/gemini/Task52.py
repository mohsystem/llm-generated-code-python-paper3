# Required: pip install cryptography
import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

KEY_SIZE_BITS = 256
SALT_SIZE_BYTES = 16
IV_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 210000

MAGIC_BYTES = b"ENCF"
VERSION = b"\x01"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BITS // 8,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_file_path: str, output_file_path: str, password: str) -> bool:
    """Encrypts a file using AES-256-GCM."""
    input_path = Path(input_file_path)
    output_path = Path(output_file_path)
    temp_output_path = output_path.with_suffix(output_path.suffix + '.tmp')

    try:
        salt = secrets.token_bytes(SALT_SIZE_BYTES)
        iv = secrets.token_bytes(IV_SIZE_BYTES)
        key = derive_key(password, salt)

        aesgcm = AESGCM(key)
        
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, None)
        ciphertext = ciphertext_and_tag[:-TAG_SIZE_BYTES]
        tag = ciphertext_and_tag[-TAG_SIZE_BYTES:]

        with open(temp_output_path, 'wb') as f:
            f.write(MAGIC_BYTES)
            f.write(VERSION)
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)
            f.write(tag)
        
        os.rename(temp_output_path, output_path)
        return True
    except (IOError, OSError) as e:
        # print(f"Encryption failed: {e}")
        if temp_output_path.exists():
            os.remove(temp_output_path)
        return False
    finally:
        # Clear sensitive data if variables are still in scope
        key = b'\x00' * (KEY_SIZE_BITS // 8)
        plaintext = b''

def decrypt_file(input_file_path: str, output_file_path: str, password: str) -> bool:
    """Decrypts a file encrypted with AES-256-GCM."""
    input_path = Path(input_file_path)
    output_path = Path(output_file_path)
    temp_output_path = output_path.with_suffix(output_path.suffix + '.tmp')

    try:
        with open(input_path, 'rb') as f:
            magic = f.read(len(MAGIC_BYTES))
            if magic != MAGIC_BYTES:
                # print("Error: Invalid file format.")
                return False
            
            version = f.read(1)
            if version != VERSION:
                # print("Error: Unsupported file version.")
                return False

            salt = f.read(SALT_SIZE_BYTES)
            iv = f.read(IV_SIZE_BYTES)
            tag = f.read(TAG_SIZE_BYTES) # Read tag from end of file first
            
            # Reposition to read ciphertext
            f.seek(len(MAGIC_BYTES) + 1 + SALT_SIZE_BYTES + IV_SIZE_BYTES)
            ciphertext = f.read()[:-TAG_SIZE_BYTES]
            tag_from_file = f.read()[-TAG_SIZE_BYTES:]
            if len(tag_from_file) != TAG_SIZE_BYTES: # handle small files
                 f.seek(input_path.stat().st_size - TAG_SIZE_BYTES)
                 tag = f.read(TAG_SIZE_BYTES)
            else:
                 tag = tag_from_file
        
        if len(salt) != SALT_SIZE_BYTES or len(iv) != IV_SIZE_BYTES or len(tag) != TAG_SIZE_BYTES:
            # print("Error: Corrupted file header.")
            return False

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
        except InvalidTag:
            # print("Decryption failed: Invalid password or tampered file.")
            return False

        with open(temp_output_path, 'wb') as f:
            f.write(plaintext)
        
        os.rename(temp_output_path, output_path)
        return True
    except (IOError, OSError) as e:
        # print(f"Decryption failed: {e}")
        if temp_output_path.exists():
            os.remove(temp_output_path)
        return False
    finally:
        key = b'\x00' * (KEY_SIZE_BITS // 8)
        plaintext = b''

def main():
    """Main function to run test cases."""
    print("Running Python tests...")
    plaintext_file = "plain.txt"
    encrypted_file = "encrypted.dat"
    decrypted_file = "decrypted.txt"
    password = "securePassword123"
    wrong_password = "wrongPassword123"

    try:
        # Setup
        with open(plaintext_file, "w", encoding="utf-8") as f:
            f.write("This is a test file for encryption.")

        # Test Case 1: Successful Encryption
        enc_success = encrypt_file(plaintext_file, encrypted_file, password)
        print(f"Test Case 1 (Encryption): {'PASSED' if enc_success else 'FAILED'}")
        assert enc_success

        # Test Case 2: Successful Decryption
        dec_success = decrypt_file(encrypted_file, decrypted_file, password)
        print(f"Test Case 2 (Decryption): {'PASSED' if dec_success else 'FAILED'}")
        assert dec_success

        # Test Case 3: Verify content
        with open(plaintext_file, "rb") as f1, open(decrypted_file, "rb") as f2:
            content_match = f1.read() == f2.read()
        print(f"Test Case 3 (Content verification): {'PASSED' if content_match else 'FAILED'}")
        assert content_match

        # Test Case 4: Decryption with wrong password
        wrong_pass_result = decrypt_file(encrypted_file, decrypted_file, wrong_password)
        print(f"Test Case 4 (Wrong password): {'PASSED' if not wrong_pass_result else 'FAILED'}")
        assert not wrong_pass_result

        # Test Case 5: Decryption of tampered file
        with open(encrypted_file, "r+b") as f:
            f.seek(50)  # Move to somewhere in the ciphertext
            f.write(b'\xff') # Flip a byte
        tampered_result = decrypt_file(encrypted_file, decrypted_file, password)
        print(f"Test Case 5 (Tampered file): {'PASSED' if not tampered_result else 'FAILED'}")
        assert not tampered_result

    finally:
        # Cleanup
        for f in [plaintext_file, encrypted_file, decrypted_file]:
            if os.path.exists(f):
                os.remove(f)
    print("Python tests finished.")

if __name__ == "__main__":
    main()