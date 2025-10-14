
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

def encrypt_aes(plain_text, key):
    try:
        # Ensure key is 16 bytes (128-bit) for AES
        key_bytes = key.encode('utf-8')[:16].ljust(16, b'\\0')
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Encrypt
        plain_bytes = plain_text.encode('utf-8')
        padded_data = pad(plain_bytes, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        # Combine IV and encrypted data
        combined = iv + encrypted
        
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    # Test case 1
    encrypted1 = encrypt_aes("Hello World", "mySecretKey12345")
    print(f"Test 1 - Encrypted: {encrypted1}")
    
    # Test case 2
    encrypted2 = encrypt_aes("Sensitive Data", "password1234567")
    print(f"Test 2 - Encrypted: {encrypted2}")
    
    # Test case 3
    encrypted3 = encrypt_aes("AES Encryption", "key123456789012")
    print(f"Test 3 - Encrypted: {encrypted3}")
    
    # Test case 4
    encrypted4 = encrypt_aes("Test Message", "secretKey123456")
    print(f"Test 4 - Encrypted: {encrypted4}")
    
    # Test case 5
    encrypted5 = encrypt_aes("Cipher Block", "encryptionKey16")
    print(f"Test 5 - Encrypted: {encrypted5}")
