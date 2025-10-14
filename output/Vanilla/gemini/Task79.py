def encrypt(message: str, key: str) -> str:
    """
    Encrypts a message using the Vigenère cipher.

    :param message: The plaintext message to encrypt.
    :param key: The secret key for encryption.
    :return: The encrypted ciphertext.
    """
    if not key:
        return message

    encrypted_message = []
    upper_key = key.upper()
    key_index = 0
    
    for char in message:
        if char.isalpha():
            key_char = upper_key[key_index % len(upper_key)]
            shift = ord(key_char) - ord('A')
            
            # Encrypt uppercase letters
            if 'A' <= char.upper() <= 'Z':
                encrypted_char_code = (ord(char.upper()) - ord('A') + shift) % 26
                encrypted_char = chr(encrypted_char_code + ord('A'))
                encrypted_message.append(encrypted_char)
                key_index += 1
            else: # Should not be reached if isalpha() is true, but for safety
                 encrypted_message.append(char)
        else:
            encrypted_message.append(char)
            
    return "".join(encrypted_message)

def main():
    test_cases = [
        ("ATTACK AT DAWN", "LEMON"),
        ("HELLO WORLD", "KEY"),
        ("Cryptography", "SECRET"),
        ("This is a test message 123!", "CIPHER"),
        ("ALLCAPS", "ALLCAPS")
    ]

    for i, (message, key) in enumerate(test_cases, 1):
        encrypted = encrypt(message, key)
        print(f"Test Case {i}:")
        print(f"  Original:  {message}")
        print(f"  Key:       {key}")
        print(f"  Encrypted: {encrypted}")
        print()

if __name__ == "__main__":
    main()