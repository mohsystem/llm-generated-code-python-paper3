
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def encrypt_message(message, secret_key):
    try:
        # Ensure the key is 16 bytes (128 bits) for AES
        key = secret_key.encode('utf-8')
        key = key[:16].ljust(16, b'\\0')
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_ECB)
        
        # Encrypt the message
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_message)
        
        # Encode to base64 for readable output
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        return f"Encryption error: {str(e)}"

if __name__ == "__main__":
    # Test case 1
    message1 = "Hello World"
    key1 = "mySecretKey12345"
    print("Test 1:")
    print(f"Message: {message1}")
    print(f"Key: {key1}")
    print(f"Encrypted: {encrypt_message(message1, key1)}")
    print()
    
    # Test case 2
    message2 = "This is a secret message"
    key2 = "password123"
    print("Test 2:")
    print(f"Message: {message2}")
    print(f"Key: {key2}")
    print(f"Encrypted: {encrypt_message(message2, key2)}")
    print()
    
    # Test case 3
    message3 = "OpenAI GPT"
    key3 = "key123"
    print("Test 3:")
    print(f"Message: {message3}")
    print(f"Key: {key3}")
    print(f"Encrypted: {encrypt_message(message3, key3)}")
    print()
    
    # Test case 4
    message4 = "Encryption test 2024"
    key4 = "supersecret"
    print("Test 4:")
    print(f"Message: {message4}")
    print(f"Key: {key4}")
    print(f"Encrypted: {encrypt_message(message4, key4)}")
    print()
    
    # Test case 5
    message5 = "12345"
    key5 = "numerickey"
    print("Test 5:")
    print(f"Message: {message5}")
    print(f"Key: {key5}")
    print(f"Encrypted: {encrypt_message(message5, key5)}")
