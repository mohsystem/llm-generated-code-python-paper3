
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class Task52:
    ALGORITHM = 'AES'
    KEY_SIZE = 32  # 256 bits
    IV_LENGTH = 12  # GCM nonce length
    TAG_LENGTH = 16  # GCM tag length

    @staticmethod
    def generate_key():
        """Generate a secure random key"""
        return os.urandom(Task52.KEY_SIZE)

    @staticmethod
    def encrypt_file(file_content, key):
        """Encrypt file content using AES-GCM"""
        if file_content is None or key is None:
            raise ValueError("File content and key cannot be None")
        
        if len(key) != Task52.KEY_SIZE:
            raise ValueError(f"Key must be {Task52.KEY_SIZE} bytes")
        
        # Generate a random IV (nonce)
        iv = os.urandom(Task52.IV_LENGTH)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(file_content) + encryptor.finalize()
        
        # Combine IV, ciphertext, and tag
        encrypted_data = iv + ciphertext + encryptor.tag
        
        return encrypted_data

    @staticmethod
    def decrypt_file(encrypted_content, key):
        """Decrypt file content using AES-GCM"""
        if encrypted_content is None or key is None:
            raise ValueError("Encrypted content and key cannot be None")
        
        if len(key) != Task52.KEY_SIZE:
            raise ValueError(f"Key must be {Task52.KEY_SIZE} bytes")
        
        if len(encrypted_content) < Task52.IV_LENGTH + Task52.TAG_LENGTH:
            raise ValueError("Invalid encrypted content")
        
        # Extract IV, ciphertext, and tag
        iv = encrypted_content[:Task52.IV_LENGTH]
        tag = encrypted_content[-Task52.TAG_LENGTH:]
        ciphertext = encrypted_content[Task52.IV_LENGTH:-Task52.TAG_LENGTH]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


def main():
    print("=== Secure File Encryption/Decryption Test Cases ===\\n")
    
    try:
        # Test Case 1: Simple text encryption/decryption
        print("Test Case 1: Simple text encryption")
        key1 = Task52.generate_key()
        text1 = b"Hello, World!"
        encrypted1 = Task52.encrypt_file(text1, key1)
        decrypted1 = Task52.decrypt_file(encrypted1, key1)
        print(f"Original: {text1.decode('utf-8')}")
        print(f"Decrypted: {decrypted1.decode('utf-8')}")
        print(f"Match: {text1 == decrypted1}\\n")

        # Test Case 2: Empty content
        print("Test Case 2: Empty content")
        key2 = Task52.generate_key()
        text2 = b""
        encrypted2 = Task52.encrypt_file(text2, key2)
        decrypted2 = Task52.decrypt_file(encrypted2, key2)
        print(f"Original length: {len(text2)}")
        print(f"Decrypted length: {len(decrypted2)}")
        print(f"Match: {len(text2) == len(decrypted2)}\\n")

        # Test Case 3: Large text
        print("Test Case 3: Large text encryption")
        key3 = Task52.generate_key()
        text3 = b"".join([f"Secure encryption test {i} ".encode() for i in range(1000)])
        encrypted3 = Task52.encrypt_file(text3, key3)
        decrypted3 = Task52.decrypt_file(encrypted3, key3)
        print(f"Original length: {len(text3)}")
        print(f"Decrypted length: {len(decrypted3)}")
        print(f"Match: {text3 == decrypted3}\\n")

        # Test Case 4: Special characters
        print("Test Case 4: Special characters")
        key4 = Task52.generate_key()
        text4 = b"Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        encrypted4 = Task52.encrypt_file(text4, key4)
        decrypted4 = Task52.decrypt_file(encrypted4, key4)
        print(f"Original: {text4.decode('utf-8')}")
        print(f"Decrypted: {decrypted4.decode('utf-8')}")
        print(f"Match: {text4 == decrypted4}\\n")

        # Test Case 5: Unicode characters
        print("Test Case 5: Unicode characters")
        key5 = Task52.generate_key()
        text5 = "Unicode: こんにちは 世界 🌍🔒".encode('utf-8')
        encrypted5 = Task52.encrypt_file(text5, key5)
        decrypted5 = Task52.decrypt_file(encrypted5, key5)
        print(f"Original: {text5.decode('utf-8')}")
        print(f"Decrypted: {decrypted5.decode('utf-8')}")
        print(f"Match: {text5 == decrypted5}\\n")

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
