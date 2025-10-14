
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class Task106:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.cipher_encrypt = PKCS1_OAEP.new(self.public_key)
        self.cipher_decrypt = PKCS1_OAEP.new(self.key)
    
    def encrypt(self, plain_text):
        if not plain_text:
            raise ValueError("Input cannot be empty")
        if isinstance(plain_text, str):
            plain_text = plain_text.encode('utf-8')
        encrypted_bytes = self.cipher_encrypt.encrypt(plain_text)
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def decrypt(self, encrypted_text):
        if not encrypted_text:
            raise ValueError("Input cannot be empty")
        encrypted_bytes = base64.b64decode(encrypted_text)
        decrypted_bytes = self.cipher_decrypt.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')

def main():
    try:
        # Test Case 1: Simple text encryption
        rsa1 = Task106()
        text1 = "Hello World"
        encrypted1 = rsa1.encrypt(text1)
        decrypted1 = rsa1.decrypt(encrypted1)
        print("Test 1:")
        print(f"Original: {text1}")
        print(f"Decrypted: {decrypted1}")
        print(f"Match: {text1 == decrypted1}")
        print()

        # Test Case 2: Numbers and special characters
        rsa2 = Task106()
        text2 = "12345!@#$%"
        encrypted2 = rsa2.encrypt(text2)
        decrypted2 = rsa2.decrypt(encrypted2)
        print("Test 2:")
        print(f"Original: {text2}")
        print(f"Decrypted: {decrypted2}")
        print(f"Match: {text2 == decrypted2}")
        print()

        # Test Case 3: Longer text
        rsa3 = Task106()
        text3 = "RSA Algorithm Test with longer message"
        encrypted3 = rsa3.encrypt(text3)
        decrypted3 = rsa3.decrypt(encrypted3)
        print("Test 3:")
        print(f"Original: {text3}")
        print(f"Decrypted: {decrypted3}")
        print(f"Match: {text3 == decrypted3}")
        print()

        # Test Case 4: Unicode characters
        rsa4 = Task106()
        text4 = "こんにちは世界"
        encrypted4 = rsa4.encrypt(text4)
        decrypted4 = rsa4.decrypt(encrypted4)
        print("Test 4:")
        print(f"Original: {text4}")
        print(f"Decrypted: {decrypted4}")
        print(f"Match: {text4 == decrypted4}")
        print()

        # Test Case 5: Single character
        rsa5 = Task106()
        text5 = "X"
        encrypted5 = rsa5.encrypt(text5)
        decrypted5 = rsa5.decrypt(encrypted5)
        print("Test 5:")
        print(f"Original: {text5}")
        print(f"Decrypted: {decrypted5}")
        print(f"Match: {text5 == decrypted5}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
