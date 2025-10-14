
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

STATIC_IV = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
BLOCK_SIZE = 16

def pad_data(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    
    padded_data = data + bytes([padding_length] * padding_length)
    return padded_data

def encrypt_data(data, key):
    padded_data = pad_data(data, BLOCK_SIZE)
    
    cipher = AES.new(key, AES.MODE_CBC, STATIC_IV)
    
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

if __name__ == "__main__":
    key = b"0123456789ABCDEF"
    
    print("Test Case 1:")
    data1 = b"Hello World!"
    encrypted1 = encrypt_data(data1, key)
    print(f"Encrypted: {base64.b64encode(encrypted1).decode()}")
    
    print("\\nTest Case 2:")
    data2 = b"Test"
    encrypted2 = encrypt_data(data2, key)
    print(f"Encrypted: {base64.b64encode(encrypted2).decode()}")
    
    print("\\nTest Case 3:")
    data3 = b"A"
    encrypted3 = encrypt_data(data3, key)
    print(f"Encrypted: {base64.b64encode(encrypted3).decode()}")
    
    print("\\nTest Case 4:")
    data4 = b"This is a longer message for encryption testing"
    encrypted4 = encrypt_data(data4, key)
    print(f"Encrypted: {base64.b64encode(encrypted4).decode()}")
    
    print("\\nTest Case 5:")
    data5 = b"1234567890123456"
    encrypted5 = encrypt_data(data5, key)
    print(f"Encrypted: {base64.b64encode(encrypted5).decode()}")
