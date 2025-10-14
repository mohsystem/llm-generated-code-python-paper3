
import base64
import os

KEY = 123

def encrypt_decrypt(data, key):
    """XOR-based encryption/decryption"""
    result = bytearray()
    for byte in data:
        result.append(byte ^ key)
    return bytes(result)

def encrypt_file(input_file, output_file, key):
    """Encrypt a file"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted = encrypt_decrypt(data, key)
    
    with open(output_file, 'wb') as f:
        f.write(encrypted)

def decrypt_file(input_file, output_file, key):
    """Decrypt a file"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    decrypted = encrypt_decrypt(data, key)
    
    with open(output_file, 'wb') as f:
        f.write(decrypted)

def encrypt_string(plaintext, key):
    """Encrypt a string and return base64 encoded result"""
    encrypted = encrypt_decrypt(plaintext.encode(), key)
    return base64.b64encode(encrypted).decode()

def decrypt_string(encrypted, key):
    """Decrypt a base64 encoded string"""
    encrypted_bytes = base64.b64decode(encrypted)
    decrypted = encrypt_decrypt(encrypted_bytes, key)
    return decrypted.decode()

def main():
    print("File Encryption/Decryption Program")
    print("===================================\\n")
    
    # Test Case 1: Encrypt and decrypt a simple string
    print("Test Case 1: Simple String Encryption")
    text1 = "Hello World!"
    encrypted1 = encrypt_string(text1, KEY)
    decrypted1 = decrypt_string(encrypted1, KEY)
    print(f"Original: {text1}")
    print(f"Encrypted: {encrypted1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {text1 == decrypted1}\\n")
    
    # Test Case 2: Encrypt and decrypt a longer text
    print("Test Case 2: Longer Text Encryption")
    text2 = "This is a test message with numbers 12345 and symbols @#$%"
    encrypted2 = encrypt_string(text2, KEY)
    decrypted2 = decrypt_string(encrypted2, KEY)
    print(f"Original: {text2}")
    print(f"Encrypted: {encrypted2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {text2 == decrypted2}\\n")
    
    # Test Case 3: Encrypt and decrypt with different key
    print("Test Case 3: Different Key")
    text3 = "Secret Message"
    custom_key = 255
    encrypted3 = encrypt_string(text3, custom_key)
    decrypted3 = decrypt_string(encrypted3, custom_key)
    print(f"Original: {text3}")
    print(f"Encrypted: {encrypted3}")
    print(f"Decrypted: {decrypted3}")
    print(f"Match: {text3 == decrypted3}\\n")
    
    # Test Case 4: Empty string
    print("Test Case 4: Empty String")
    text4 = ""
    encrypted4 = encrypt_string(text4, KEY)
    decrypted4 = decrypt_string(encrypted4, KEY)
    print(f"Original: '{text4}'")
    print(f"Encrypted: '{encrypted4}'")
    print(f"Decrypted: '{decrypted4}'")
    print(f"Match: {text4 == decrypted4}\\n")
    
    # Test Case 5: File encryption/decryption
    print("Test Case 5: File Encryption/Decryption")
    try:
        original_file = "test_input.txt"
        encrypted_file = "test_encrypted.bin"
        decrypted_file = "test_decrypted.txt"
        
        # Create a test file
        with open(original_file, 'w') as f:
            f.write("This is a test file content.\\nLine 2 with more data.")
        
        # Encrypt file
        encrypt_file(original_file, encrypted_file, KEY)
        print(f"File encrypted: {encrypted_file}")
        
        # Decrypt file
        decrypt_file(encrypted_file, decrypted_file, KEY)
        print(f"File decrypted: {decrypted_file}")
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            content = f.read()
        print(f"Decrypted content: {content}")
        
    except Exception as e:
        print(f"File operation: {e}")

if __name__ == "__main__":
    main()
