
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os
import base64

class Task51:
    @staticmethod
    def generate_key():
        """Generate a secure random 256-bit AES key"""
        key = os.urandom(32)
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def encrypt(plaintext, base64_key):
        """Encrypt plaintext using AES-GCM"""
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        if not base64_key:
            raise ValueError("Key cannot be empty")
        
        key = base64.b64decode(base64_key)
        
        iv = os.urandom(12)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        encrypted_with_iv_and_tag = iv + encryptor.tag + ciphertext
        
        return base64.b64encode(encrypted_with_iv_and_tag).decode('utf-8')
    
    @staticmethod
    def decrypt(encrypted_text, base64_key):
        """Decrypt ciphertext using AES-GCM"""
        if not encrypted_text:
            raise ValueError("Encrypted text cannot be empty")
        if not base64_key:
            raise ValueError("Key cannot be empty")
        
        key = base64.b64decode(base64_key)
        
        encrypted_with_iv_and_tag = base64.b64decode(encrypted_text)
        
        iv = encrypted_with_iv_and_tag[:12]
        tag = encrypted_with_iv_and_tag[12:28]
        ciphertext = encrypted_with_iv_and_tag[28:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')


def main():
    try:
        task = Task51()
        key = task.generate_key()
        print(f"Generated Key: {key}\\n")
        
        # Test Case 1
        plaintext1 = "Hello, World!"
        encrypted1 = task.encrypt(plaintext1, key)
        decrypted1 = task.decrypt(encrypted1, key)
        print("Test Case 1:")
        print(f"Original: {plaintext1}")
        print(f"Encrypted: {encrypted1}")
        print(f"Decrypted: {decrypted1}")
        print(f"Match: {plaintext1 == decrypted1}\\n")
        
        # Test Case 2
        plaintext2 = "Secure Encryption 2024!"
        encrypted2 = task.encrypt(plaintext2, key)
        decrypted2 = task.decrypt(encrypted2, key)
        print("Test Case 2:")
        print(f"Original: {plaintext2}")
        print(f"Encrypted: {encrypted2}")
        print(f"Decrypted: {decrypted2}")
        print(f"Match: {plaintext2 == decrypted2}\\n")
        
        # Test Case 3
        plaintext3 = "Special characters: @#$%^&*()"
        encrypted3 = task.encrypt(plaintext3, key)
        decrypted3 = task.decrypt(encrypted3, key)
        print("Test Case 3:")
        print(f"Original: {plaintext3}")
        print(f"Encrypted: {encrypted3}")
        print(f"Decrypted: {decrypted3}")
        print(f"Match: {plaintext3 == decrypted3}\\n")
        
        # Test Case 4
        plaintext4 = "1234567890"
        encrypted4 = task.encrypt(plaintext4, key)
        decrypted4 = task.decrypt(encrypted4, key)
        print("Test Case 4:")
        print(f"Original: {plaintext4}")
        print(f"Encrypted: {encrypted4}")
        print(f"Decrypted: {decrypted4}")
        print(f"Match: {plaintext4 == decrypted4}\\n")
        
        # Test Case 5
        plaintext5 = "This is a longer text to test encryption with multiple words and sentences."
        encrypted5 = task.encrypt(plaintext5, key)
        decrypted5 = task.decrypt(encrypted5, key)
        print("Test Case 5:")
        print(f"Original: {plaintext5}")
        print(f"Encrypted: {encrypted5}")
        print(f"Decrypted: {decrypted5}")
        print(f"Match: {plaintext5 == decrypted5}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
