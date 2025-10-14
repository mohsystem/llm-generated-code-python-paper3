def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts a string using a repeating key XOR cipher and returns the hex-encoded result.
    This is a simple educational cipher and is NOT secure for real-world use.

    :param plaintext: The string to encrypt.
    :param key: The encryption key.
    :return: The hex-encoded encrypted string, or the original plaintext if the key is empty.
    """
    if not key or not plaintext:
        return plaintext

    encrypted_chars = []
    for i in range(len(plaintext)):
        key_char = key[i % len(key)]
        plaintext_char = plaintext[i]
        encrypted_byte = ord(plaintext_char) ^ ord(key_char)
        encrypted_chars.append(f'{encrypted_byte:02x}')
    
    return "".join(encrypted_chars)

def main():
    """ Main function with test cases. """
    test_cases = [
        ("Hello, World!", "KEY"),
        ("This is a longer test message.", "SECRET"),
        ("Short", "LONGERKEY"),
        ("12345!@#$%", "NUMSYM"),
        ("Test with empty key", "")
    ]
    
    print("Python Encryption Test Cases:")
    for plaintext, key in test_cases:
        encrypted = encrypt(plaintext, key)
        print(f'Plaintext : "{plaintext}", Key: "{key}"')
        print(f'Encrypted : {encrypted}')
        print("--------------------")

if __name__ == "__main__":
    main()