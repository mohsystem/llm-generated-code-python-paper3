
def encrypt(input_str):
    if input_str is None or len(input_str) == 0:
        return input_str
    
    encrypted = []
    shift = 3  # Caesar cipher shift
    
    for ch in input_str:
        if ch.isupper():
            encrypted_char = chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
            encrypted.append(encrypted_char)
        elif ch.islower():
            encrypted_char = chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
            encrypted.append(encrypted_char)
        elif ch.isdigit():
            encrypted_char = chr((ord(ch) - ord('0') + shift) % 10 + ord('0'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(ch)
    
    return ''.join(encrypted)


if __name__ == "__main__":
    # Test case 1: Simple lowercase string
    test1 = "hello"
    print(f"Test 1 - Input: {test1}")
    print(f"Encrypted: {encrypt(test1)}")
    print()
    
    # Test case 2: Mixed case string
    test2 = "HelloWorld"
    print(f"Test 2 - Input: {test2}")
    print(f"Encrypted: {encrypt(test2)}")
    print()
    
    # Test case 3: String with numbers
    test3 = "Test123"
    print(f"Test 3 - Input: {test3}")
    print(f"Encrypted: {encrypt(test3)}")
    print()
    
    # Test case 4: String with special characters
    test4 = "Hello, World! 2024"
    print(f"Test 4 - Input: {test4}")
    print(f"Encrypted: {encrypt(test4)}")
    print()
    
    # Test case 5: Edge case with letters near end of alphabet
    test5 = "xyz XYZ 789"
    print(f"Test 5 - Input: {test5}")
    print(f"Encrypted: {encrypt(test5)}")
    print()
