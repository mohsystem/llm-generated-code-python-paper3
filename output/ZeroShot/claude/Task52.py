
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Task52:
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    
    @staticmethod
    def generate_key(password):
        return hashlib.sha256(password.encode('utf-8')).digest()
    
    @staticmethod
    def encrypt_data(data, password):
        key = Task52.generate_key(password)
        iv = get_random_bytes(Task52.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        padded_data = pad(data, Task52.BLOCK_SIZE)
        encrypted = cipher.encrypt(padded_data)
        
        return iv + encrypted
    
    @staticmethod
    def decrypt_data(encrypted_data, password):
        key = Task52.generate_key(password)
        iv = encrypted_data[:Task52.BLOCK_SIZE]
        encrypted_content = encrypted_data[Task52.BLOCK_SIZE:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_content)
        
        return unpad(decrypted, Task52.BLOCK_SIZE)
    
    @staticmethod
    def encrypt_file(input_file, output_file, password):
        with open(input_file, 'rb') as f:
            file_content = f.read()
        
        encrypted = Task52.encrypt_data(file_content, password)
        
        with open(output_file, 'wb') as f:
            f.write(encrypted)
    
    @staticmethod
    def decrypt_file(input_file, output_file, password):
        with open(input_file, 'rb') as f:
            encrypted_content = f.read()
        
        decrypted = Task52.decrypt_data(encrypted_content, password)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted)


if __name__ == "__main__":
    # Test Case 1: Simple text encryption/decryption
    print("Test Case 1: Simple text encryption/decryption")
    text1 = "Hello, World!"
    password1 = "SecurePassword123"
    encrypted1 = Task52.encrypt_data(text1, password1)
    decrypted1 = Task52.decrypt_data(encrypted1, password1).decode('utf-8')
    print(f"Original: {text1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {text1 == decrypted1}\\n")
    
    # Test Case 2: Longer text with special characters
    print("Test Case 2: Longer text with special characters")
    text2 = "This is a secure message with special chars: @#$%^&*()"
    password2 = "AnotherSecurePass456"
    encrypted2 = Task52.encrypt_data(text2, password2)
    decrypted2 = Task52.decrypt_data(encrypted2, password2).decode('utf-8')
    print(f"Original: {text2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {text2 == decrypted2}\\n")
    
    # Test Case 3: Empty string
    print("Test Case 3: Empty string")
    text3 = ""
    password3 = "password"
    encrypted3 = Task52.encrypt_data(text3, password3)
    decrypted3 = Task52.decrypt_data(encrypted3, password3).decode('utf-8')
    print(f"Original length: {len(text3)}")
    print(f"Decrypted length: {len(decrypted3)}")
    print(f"Match: {text3 == decrypted3}\\n")
    
    # Test Case 4: Numeric data
    print("Test Case 4: Numeric data")
    text4 = "1234567890"
    password4 = "NumericPass999"
    encrypted4 = Task52.encrypt_data(text4, password4)
    decrypted4 = Task52.decrypt_data(encrypted4, password4).decode('utf-8')
    print(f"Original: {text4}")
    print(f"Decrypted: {decrypted4}")
    print(f"Match: {text4 == decrypted4}\\n")
    
    # Test Case 5: File encryption/decryption
    print("Test Case 5: File encryption/decryption")
    test_content = "This is a test file content for encryption."
    
    with open("test_input.txt", "w") as f:
        f.write(test_content)
    
    Task52.encrypt_file("test_input.txt", "test_encrypted.bin", "FilePassword123")
    Task52.decrypt_file("test_encrypted.bin", "test_decrypted.txt", "FilePassword123")
    
    with open("test_decrypted.txt", "r") as f:
        decrypted_content = f.read()
    
    print(f"Original file content: {test_content}")
    print(f"Decrypted file content: {decrypted_content}")
    print(f"Match: {test_content == decrypted_content}")
    
    # Cleanup
    if os.path.exists("test_input.txt"):
        os.remove("test_input.txt")
    if os.path.exists("test_encrypted.bin"):
        os.remove("test_encrypted.bin")
    if os.path.exists("test_decrypted.txt"):
        os.remove("test_decrypted.txt")
