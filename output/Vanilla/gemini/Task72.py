# Note: This code requires the 'pycryptodome' package.
# You can install it using: pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# 1. Create a static initialization vector (IV).
STATIC_IV = b'abcdefghijklmnop'
# A secret key is also required for AES. Using a 128-bit key (16 bytes).
SECRET_KEY = b'0123456789abcdef'

def encrypt(plain_text_bytes, key, iv):
    """
    Encrypts data using AES in CBC mode.
    """
    # 2. Initialize a cipher using AES in CBC mode with the static IV.
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 3. Pad the input data to match the block size required by the cipher.
    # AES.block_size is 16 bytes.
    padded_data = pad(plain_text_bytes, AES.block_size)

    # 4. Encrypt the padded data using the cipher.
    encrypted_data = cipher.encrypt(padded_data)

    # 5. Return the encrypted data.
    return encrypted_data

class Task72:
    @staticmethod
    def main():
        test_cases = [
            "",
            "Hello",
            "16-byte message!", # Exactly 16 bytes, will add a full padding block
            "This is a longer test message for AES encryption.",
            "!@#$%^&*()_+"
        ]

        print("Python AES/CBC Encryption Test Cases:")
        for i, test_str in enumerate(test_cases):
            try:
                # Convert string to bytes for encryption
                plain_text_bytes = test_str.encode('utf-8')
                encrypted = encrypt(plain_text_bytes, SECRET_KEY, STATIC_IV)
                print(f"Test Case {i + 1}:")
                print(f"  Plaintext:  \"{test_str}\"")
                # Using Base64 to represent the binary encrypted data
                print(f"  Encrypted (Base64): {base64.b64encode(encrypted).decode('utf-8')}")
                print()
            except Exception as e:
                print(f"Error during encryption for test case {i + 1}: {e}")

if __name__ == "__main__":
    Task72.main()