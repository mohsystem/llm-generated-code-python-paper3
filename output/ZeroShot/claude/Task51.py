
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

class Task51:
    @staticmethod
    def encrypt(plain_text, secret_key):
        try:
            key = Task51.generate_key(secret_key)
            cipher = AES.new(key, AES.MODE_ECB)
            padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
            encrypted_bytes = cipher.encrypt(padded_text)
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt(encrypted_text, secret_key):
        try:
            key = Task51.generate_key(secret_key)
            cipher = AES.new(key, AES.MODE_ECB)
            decoded_bytes = base64.b64decode(encrypted_text)
            decrypted_bytes = cipher.decrypt(decoded_bytes)
            unpadded_text = unpad(decrypted_bytes, AES.block_size)
            return unpadded_text.decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def generate_key(secret_key):
        sha = hashlib.sha256()
        sha.update(secret_key.encode('utf-8'))
        return sha.digest()[:16]

if __name__ == "__main__":
    # Test case 1
    text1 = "Hello World"
    key1 = "mySecretKey123"
    encrypted1 = Task51.encrypt(text1, key1)
    decrypted1 = Task51.decrypt(encrypted1, key1)
    print("Test 1:")
    print(f"Original: {text1}")
    print(f"Encrypted: {encrypted1}")
    print(f"Decrypted: {decrypted1}")
    print()
    
    # Test case 2
    text2 = "Secure Programming 2024"
    key2 = "strongPassword!@#"
    encrypted2 = Task51.encrypt(text2, key2)
    decrypted2 = Task51.decrypt(encrypted2, key2)
    print("Test 2:")
    print(f"Original: {text2}")
    print(f"Encrypted: {encrypted2}")
    print(f"Decrypted: {decrypted2}")
    print()
    
    # Test case 3
    text3 = "12345 Special!@#$%"
    key3 = "encryptionKey789"
    encrypted3 = Task51.encrypt(text3, key3)
    decrypted3 = Task51.decrypt(encrypted3, key3)
    print("Test 3:")
    print(f"Original: {text3}")
    print(f"Encrypted: {encrypted3}")
    print(f"Decrypted: {decrypted3}")
    print()
    
    # Test case 4
    text4 = "The quick brown fox jumps over the lazy dog"
    key4 = "testKey2024"
    encrypted4 = Task51.encrypt(text4, key4)
    decrypted4 = Task51.decrypt(encrypted4, key4)
    print("Test 4:")
    print(f"Original: {text4}")
    print(f"Encrypted: {encrypted4}")
    print(f"Decrypted: {decrypted4}")
    print()
    
    # Test case 5
    text5 = "AES Encryption Test"
    key5 = "anotherSecretKey"
    encrypted5 = Task51.encrypt(text5, key5)
    decrypted5 = Task51.decrypt(encrypted5, key5)
    print("Test 5:")
    print(f"Original: {text5}")
    print(f"Encrypted: {encrypted5}")
    print(f"Decrypted: {decrypted5}")
