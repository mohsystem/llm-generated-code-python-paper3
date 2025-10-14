
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

KEY_LENGTH = 32  # 256 bits
ITERATION_COUNT = 65536
SALT_LENGTH = 16
IV_LENGTH = 16

def encrypt_message(message, secret_key):
    try:
        # Generate random salt
        salt = get_random_bytes(SALT_LENGTH)
        
        # Derive key from password using PBKDF2
        key = PBKDF2(secret_key, salt, dkLen=KEY_LENGTH, count=ITERATION_COUNT)
        
        # Generate random IV
        iv = get_random_bytes(IV_LENGTH)
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad message to be multiple of 16 bytes
        padding_length = AES.block_size - len(message.encode('utf-8')) % AES.block_size
        padded_message = message.encode('utf-8') + bytes([padding_length] * padding_length)
        
        encrypted = cipher.encrypt(padded_message)
        
        # Combine salt + IV + encrypted data
        combined = salt + iv + encrypted
        
        # Encode to Base64
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {str(e)}")

def main():
    # Test cases
    messages = [
        "Hello, World!",
        "Secure message 123",
        "This is a confidential document",
        "Test@#$%^&*()",
        "Another secret message"
    ]
    
    keys = [
        "MySecretKey123",
        "P@ssw0rd!Strong",
        "EncryptionKey456",
        "SecurePassword789",
        "TopSecret2024"
    ]
    
    print("=== Encryption Test Cases ===\\n")
    for i in range(len(messages)):
        print(f"Test Case {i + 1}:")
        print(f"Original Message: {messages[i]}")
        print(f"Secret Key: {keys[i]}")
        encrypted = encrypt_message(messages[i], keys[i])
        print(f"Encrypted Message: {encrypted}")
        print(f"Encrypted Length: {len(encrypted)} characters")
        print()

if __name__ == "__main__":
    main()
