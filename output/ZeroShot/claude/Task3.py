
def is_pangram(sentence):
    if not sentence:
        return False
    
    letters = set()
    lower_case = sentence.lower()
    
    for c in lower_case:
        if 'a' <= c <= 'z':
            letters.add(c)
    
    return len(letters) == 26


if __name__ == "__main__":
    # Test cases
    print("Test 1:", is_pangram("The quick brown fox jumps over the lazy dog"))  # True
    print("Test 2:", is_pangram("Hello World"))  # False
    print("Test 3:", is_pangram("abcdefghijklmnopqrstuvwxyz"))  # True
    print("Test 4:", is_pangram("Pack my box with five dozen liquor jugs"))  # True
    print("Test 5:", is_pangram("This is not a pangram sentence"))  # False
