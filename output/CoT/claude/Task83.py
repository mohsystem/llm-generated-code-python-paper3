
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

class EncryptionResult:
    def __init__(self, encrypted_data, iv):
        self.encrypted_data = encrypted_data
        self.iv = iv
    
    def to_base64(self):
        return base64.b64encode(self.encrypted_data).decode('utf-8')
    
    def get_iv_base64(self):
        return base64.b64encode(self.iv).decode('utf-8')

def encrypt_data(plaintext, key_bytes):
    """\n    Encrypts data using AES in CBC mode with secure random IV\n    \n    Args:\n        plaintext: bytes to encrypt\n        key_bytes: AES key (must be 16, 24, or 32 bytes)\n    \n    Returns:\n        EncryptionResult containing encrypted data and IV\n    """
    if not plaintext:
        raise ValueError("Plaintext cannot be None or empty")
    
    if not key_bytes or len(key_bytes) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes")
    
    # Generate random IV using secure random
    iv = get_random_bytes(16)
    
    # Create cipher with CBC mode
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    
    # Pad plaintext to block size and encrypt
    padded_plaintext = pad(plaintext, AES.block_size)
    encrypted_data = cipher.encrypt(padded_plaintext)
    
    return EncryptionResult(encrypted_data, iv)

def generate_secure_key(key_size):
    """\n    Generate a secure random key\n    \n    Args:\n        key_size: key size in bits (128, 192, or 256)\n    \n    Returns:\n        bytes: random key\n    """
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    
    return get_random_bytes(key_size // 8)

def main():
    print("AES CBC Encryption Test Cases\\n")
    
    # Test Case 1: Standard encryption with 256-bit key
    print("Test Case 1: 256-bit key encryption")
    key1 = generate_secure_key(256)
    plaintext1 = "Hello, Secure World!"
    result1 = encrypt_data(plaintext1.encode('utf-8'), key1)
    print(f"Plaintext: {plaintext1}")
    print(f"Encrypted (Base64): {result1.to_base64()}")
    print(f"IV (Base64): {result1.get_iv_base64()}")
    print()
    
    # Test Case 2: Encryption with 128-bit key
    print("Test Case 2: 128-bit key encryption")
    key2 = generate_secure_key(128)
    plaintext2 = "Sensitive Data 123"
    result2 = encrypt_data(plaintext2.encode('utf-8'), key2)
    print(f"Plaintext: {plaintext2}")
    print(f"Encrypted (Base64): {result2.to_base64()}")
    print(f"IV (Base64): {result2.get_iv_base64()}")
    print()
    
    # Test Case 3: Large data encryption
    print("Test Case 3: Large data encryption")
    key3 = generate_secure_key(256)
    plaintext3 = ("This is a much longer message that contains multiple sentences. "
                 "It demonstrates the encryption of larger data blocks using AES CBC mode.")
    result3 = encrypt_data(plaintext3.encode('utf-8'), key3)
    print(f"Plaintext length: {len(plaintext3)} bytes")
    print(f"Encrypted (Base64): {result3.to_base64()}")
    print(f"IV (Base64): {result3.get_iv_base64()}")
    print()
    
    # Test Case 4: Special characters encryption
    print("Test Case 4: Special characters encryption")
    key4 = generate_secure_key(192)
    plaintext4 = "Special chars: @#$%^&*()_+-={}[]|:;<>?,./~`"
    result4 = encrypt_data(plaintext4.encode('utf-8'), key4)
    print(f"Plaintext: {plaintext4}")
    print(f"Encrypted (Base64): {result4.to_base64()}")
    print(f"IV (Base64): {result4.get_iv_base64()}")
    print()
    
    # Test Case 5: Verify different IVs produce different ciphertexts
    print("Test Case 5: Same plaintext, different IVs")
    key5 = generate_secure_key(256)
    plaintext5 = "Same message"
    result5a = encrypt_data(plaintext5.encode('utf-8'), key5)
    result5b = encrypt_data(plaintext5.encode('utf-8'), key5)
    print(f"Plaintext: {plaintext5}")
    print(f"Encrypted 1 (Base64): {result5a.to_base64()}")
    print(f"Encrypted 2 (Base64): {result5b.to_base64()}")
    print(f"Are ciphertexts different? {result5a.encrypted_data != result5b.encrypted_data}")

if __name__ == "__main__":
    main()
