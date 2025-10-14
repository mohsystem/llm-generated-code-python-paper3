
def is_pangram(sentence):
    if not sentence:
        return False
    
    alphabet = [False] * 26
    lower_sentence = sentence.lower()
    
    for char in lower_sentence:
        if 'a' <= char <= 'z':
            alphabet[ord(char) - ord('a')] = True
    
    return all(alphabet)


if __name__ == "__main__":
    # Test case 1
    test1 = "The quick brown fox jumps over the lazy dog"
    print(f'Test 1: "{test1}" -> {is_pangram(test1)}')
    
    # Test case 2
    test2 = "Hello World"
    print(f'Test 2: "{test2}" -> {is_pangram(test2)}')
    
    # Test case 3
    test3 = "abcdefghijklmnopqrstuvwxyz"
    print(f'Test 3: "{test3}" -> {is_pangram(test3)}')
    
    # Test case 4
    test4 = "Pack my box with five dozen liquor jugs!"
    print(f'Test 4: "{test4}" -> {is_pangram(test4)}')
    
    # Test case 5
    test5 = "1234567890!@#$%^&*()"
    print(f'Test 5: "{test5}" -> {is_pangram(test5)}')
