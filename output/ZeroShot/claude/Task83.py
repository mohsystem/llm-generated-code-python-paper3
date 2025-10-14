
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

def encrypt_aes(key, plain_text):
    try:
        # Generate a random IV (Initialization Vector)
        iv = get_random_bytes(16)
        
        # Prepare the key (ensure it's 16 bytes for AES-128)\n        key_bytes = key.encode('utf-8')\n        key_bytes = key_bytes[:16].ljust(16, b'\\0')\n        \n        # Create cipher object\n        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)\n        \n        # Pad and encrypt the plaintext\n        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)\n        encrypted = cipher.encrypt(padded_text)\n        \n        # Combine IV and encrypted data\n        combined = iv + encrypted\n        \n        # Return Base64 encoded result\n        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    # Test cases
    keys = [
        "mySecretKey12345",
        "anotherKey456789",
        "testKey123456789",
        "secureKey9876543",
        "randomKey1122334"
    ]
    
    plain_texts = [
        "Hello World",
        "This is a test message",
        "AES encryption in CBC mode",
        "Secure data transmission",
        "Testing encryption"
    ]
    
    for i in range(len(keys)):
        encrypted = encrypt_aes(keys[i], plain_texts[i])
        print(f"Test Case {i + 1}:")
        print(f"Key: {keys[i]}")
        print(f"Plain Text: {plain_texts[i]}")
        print(f"Encrypted: {encrypted}")
        print()
