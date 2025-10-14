
def is_pangram(text):
    if text is None or len(text) == 0:
        return False
    
    alphabet_set = set()
    lower_text = text.lower()
    
    for char in lower_text:
        if 'a' <= char <= 'z':
            alphabet_set.add(char)
    
    return len(alphabet_set) == 26


if __name__ == "__main__":
    # Test case 1: Classic pangram
    print("Test 1:", is_pangram("The quick brown fox jumps over the lazy dog"))
    
    # Test case 2: Pangram with numbers and punctuation
    print("Test 2:", is_pangram("Pack my box with five dozen liquor jugs!123"))
    
    # Test case 3: Not a pangram
    print("Test 3:", is_pangram("Hello World"))
    
    # Test case 4: Empty string
    print("Test 4:", is_pangram(""))
    
    # Test case 5: All letters with special characters
    print("Test 5:", is_pangram("abcdefghijklmnopqrstuvwxyz!!!"))
