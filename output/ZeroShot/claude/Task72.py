
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

class Task72:
    STATIC_IV = bytes(16)  # Static IV (all zeros)
    
    @staticmethod
    def encrypt_data(data, key):
        # Create static IV and initialize cipher with AES in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, Task72.STATIC_IV)
        
        # Pad the input data to match block size (16 bytes for AES)
        padded_data = pad(data, AES.block_size)
        
        # Encrypt the padded data
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data

def main():
    # Test cases with 128-bit (16 bytes) key
    key = b'1234567890123456'
    
    # Test case 1
    input1 = b"Hello World!"
    encrypted1 = Task72.encrypt_data(input1, key)
    print(f"Test 1 - Input: {input1.decode()}")
    print(f"Encrypted: {base64.b64encode(encrypted1).decode()}")
    
    # Test case 2
    input2 = b"SecureData"
    encrypted2 = Task72.encrypt_data(input2, key)
    print(f"\\nTest 2 - Input: {input2.decode()}")
    print(f"Encrypted: {base64.b64encode(encrypted2).decode()}")
    
    # Test case 3
    input3 = b"A"
    encrypted3 = Task72.encrypt_data(input3, key)
    print(f"\\nTest 3 - Input: {input3.decode()}")
    print(f"Encrypted: {base64.b64encode(encrypted3).decode()}")
    
    # Test case 4
    input4 = b"This is a longer message to test encryption"
    encrypted4 = Task72.encrypt_data(input4, key)
    print(f"\\nTest 4 - Input: {input4.decode()}")
    print(f"Encrypted: {base64.b64encode(encrypted4).decode()}")
    
    # Test case 5
    input5 = b"1234567890123456"  # Exactly one block
    encrypted5 = Task72.encrypt_data(input5, key)
    print(f"\\nTest 5 - Input: {input5.decode()}")
    print(f"Encrypted: {base64.b64encode(encrypted5).decode()}")

if __name__ == "__main__":
    main()
