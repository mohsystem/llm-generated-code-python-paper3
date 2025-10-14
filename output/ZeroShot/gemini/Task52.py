# Note: This code requires the 'cryptography' library.
# Install it using: pip install cryptography
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
KEY_SIZE = 32  # 256-bit key
SALT_SIZE = 16
IV_SIZE = 12   # Nonce size for GCM
TAG_SIZE = 16  # Authentication tag size
PBKDF2_ITERATIONS = 65536
BUFFER_SIZE = 4096

def get_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_file: str, output_file: str, password: str) -> bool:
    """Encrypts a file using AES-256-GCM."""
    try:
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key = get_key_from_password(password, salt)
        aesgcm = AESGCM(key)

        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(iv)
            
            while True:
                chunk = f_in.read(BUFFER_SIZE)
                if not chunk:
                    break
                ciphertext = aesgcm.encrypt(iv, chunk, None)
                f_out.write(ciphertext) # This includes the auth tag for the last block
        return True
    except Exception as e:
        print(f"Encryption error: {e}")
        return False

def decrypt_file(input_file: str, output_file: str, password: str) -> bool:
    """Decrypts a file using AES-256-GCM."""
    try:
        with open(input_file, 'rb') as f_in:
            salt = f_in.read(SALT_SIZE)
            iv = f_in.read(IV_SIZE)
            ciphertext_with_tag = f_in.read()

        key = get_key_from_password(password, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

        with open(output_file, 'wb') as f_out:
            f_out.write(plaintext)
        
        return True
    except Exception as e:
        # InvalidTag exception for wrong password or tampered file
        # print(f"Decryption error: {e}")
        return False

def main():
    """Main function to run test cases."""
    print("\nRunning Python Tests...")
    password = "my-very-secret-password-123"

    def cleanup(*files):
        for f in files:
            if os.path.exists(f):
                os.remove(f)

    # Test Case 1: Simple text file
    try:
        content = b"This is a test file for encryption."
        with open("plain1.txt", "wb") as f: f.write(content)
        encrypt_file("plain1.txt", "encrypted1.enc", password)
        decrypt_file("encrypted1.enc", "decrypted1.txt", password)
        with open("decrypted1.txt", "rb") as f:
            decrypted_content = f.read()
        assert content == decrypted_content
        print("Test Case 1 (Simple Text): PASSED")
    except Exception as e:
        print(f"Test Case 1 (Simple Text): FAILED - {e}")
    finally:
        cleanup("plain1.txt", "encrypted1.enc", "decrypted1.txt")

    # Test Case 2: Large file
    try:
        content = os.urandom(1024 * 100) # 100 KB
        with open("plain2.bin", "wb") as f: f.write(content)
        encrypt_file("plain2.bin", "encrypted2.enc", password)
        decrypt_file("encrypted2.enc", "decrypted2.bin", password)
        with open("decrypted2.bin", "rb") as f:
            decrypted_content = f.read()
        assert content == decrypted_content
        print("Test Case 2 (Large File): PASSED")
    except Exception as e:
        print(f"Test Case 2 (Large File): FAILED - {e}")
    finally:
        cleanup("plain2.bin", "encrypted2.enc", "decrypted2.bin")
        
    # Test Case 3: Empty file
    try:
        content = b""
        with open("plain3.txt", "wb") as f: f.write(content)
        encrypt_file("plain3.txt", "encrypted3.enc", password)
        decrypt_file("encrypted3.enc", "decrypted3.txt", password)
        with open("decrypted3.txt", "rb") as f:
            decrypted_content = f.read()
        assert content == decrypted_content
        print("Test Case 3 (Empty File): PASSED")
    except Exception as e:
        print(f"Test Case 3 (Empty File): FAILED - {e}")
    finally:
        cleanup("plain3.txt", "encrypted3.enc", "decrypted3.txt")

    # Test Case 4: Wrong password
    try:
        content = b"wrong password test"
        with open("plain4.txt", "wb") as f: f.write(content)
        encrypt_file("plain4.txt", "encrypted4.enc", password)
        result = decrypt_file("encrypted4.enc", "decrypted4.txt", "wrong-password")
        assert not result
        assert not os.path.exists("decrypted4.txt")
        print("Test Case 4 (Wrong Password): PASSED")
    except Exception as e:
        print(f"Test Case 4 (Wrong Password): FAILED - {e}")
    finally:
        cleanup("plain4.txt", "encrypted4.enc", "decrypted4.txt")
        
    # Test Case 5: Tampered file
    try:
        content = b"tampered file test"
        with open("plain5.txt", "wb") as f: f.write(content)
        encrypt_file("plain5.txt", "encrypted5.enc", password)

        with open("encrypted5.enc", "r+b") as f:
            f.seek(-5, os.SEEK_END)
            byte = f.read(1)
            f.seek(-1, os.SEEK_CUR)
            f.write(bytes([byte[0] ^ 1]))

        result = decrypt_file("encrypted5.enc", "decrypted5.txt", password)
        assert not result
        print("Test Case 5 (Tampered File): PASSED")
    except Exception as e:
        print(f"Test Case 5 (Tampered File): FAILED - {e}")
    finally:
        cleanup("plain5.txt", "encrypted5.enc", "decrypted5.txt")


if __name__ == "__main__":
    main()