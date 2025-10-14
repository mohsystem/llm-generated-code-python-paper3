def encrypt(text, shift):
    """
    Encrypts a string using the Caesar cipher algorithm.
    :param text: The string to encrypt.
    :param shift: The number of positions to shift letters.
    :return: The encrypted string.
    """
    if text is None:
        return None
        
    encrypted_chars = []
    for char in text:
        if 'a' <= char <= 'z':
            shifted_char_code = (ord(char) - ord('a') + shift) % 26 + ord('a')
            encrypted_chars.append(chr(shifted_char_code))
        elif 'A' <= char <= 'Z':
            shifted_char_code = (ord(char) - ord('A') + shift) % 26 + ord('A')
            encrypted_chars.append(chr(shifted_char_code))
        else:
            encrypted_chars.append(char)
    return "".join(encrypted_chars)

def main():
    # Test Case 1
    text1 = "Hello, World!"
    shift1 = 3
    print("Test Case 1:")
    print(f"Original:  {text1}")
    print(f"Shift:     {shift1}")
    print(f"Encrypted: {encrypt(text1, shift1)}")
    print("--------------------")

    # Test Case 2
    text2 = "Programming is fun!"
    shift2 = 7
    print("Test Case 2:")
    print(f"Original:  {text2}")
    print(f"Shift:     {shift2}")
    print(f"Encrypted: {encrypt(text2, shift2)}")
    print("--------------------")

    # Test Case 3
    text3 = "Caesar Cipher"
    shift3 = 13 # ROT13
    print("Test Case 3:")
    print(f"Original:  {text3}")
    print(f"Shift:     {shift3}")
    print(f"Encrypted: {encrypt(text3, shift3)}")
    print("--------------------")

    # Test Case 4
    text4 = "All your base are belong to us."
    shift4 = 1
    print("Test Case 4:")
    print(f"Original:  {text4}")
    print(f"Shift:     {shift4}")
    print(f"Encrypted: {encrypt(text4, shift4)}")
    print("--------------------")

    # Test Case 5
    text5 = "Testing with numbers 123 and symbols !@#."
    shift5 = 5
    print("Test Case 5:")
    print(f"Original:  {text5}")
    print(f"Shift:     {shift5}")
    print(f"Encrypted: {encrypt(text5, shift5)}")
    print("--------------------")

if __name__ == "__main__":
    main()