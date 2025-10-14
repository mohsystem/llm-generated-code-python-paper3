
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def encrypt(message, secret_key):
    try:
        # Ensure key is 16 bytes (128-bit)
        key_bytes = secret_key.encode('utf-8')[:16].ljust(16, b'\\0')
        
        # Create cipher for encryption
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        
        # Pad and encrypt the message
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_message)
        
        # Return Base64 encoded string
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    # Test case 1
    result1 = encrypt("Hello World", "mySecretKey12345")
    print(f"Test 1 - Encrypted: {result1}")
    
    # Test case 2
    result2 = encrypt("Secure Message", "password1234567")
    print(f"Test 2 - Encrypted: {result2}")
    
    # Test case 3
    result3 = encrypt("Testing 123", "key123456789012")
    print(f"Test 3 - Encrypted: {result3}")
    
    # Test case 4
    result4 = encrypt("Encryption Test", "secretKey098765")
    print(f"Test 4 - Encrypted: {result4}")
    
    # Test case 5
    result5 = encrypt("Java Crypto", "myKey1234567890")
    print(f"Test 5 - Encrypted: {result5}")
