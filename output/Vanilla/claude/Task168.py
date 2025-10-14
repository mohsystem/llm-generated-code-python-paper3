
def tweakLetters(s, tweaks):
    result = ""
    for i in range(len(s)):
        tweaked_char = chr(ord(s[i]) + tweaks[i])
        result += tweaked_char
    return result

if __name__ == "__main__":
    # Test case 1
    print(tweakLetters("apple", [0, 1, -1, 0, -1]))  # "aqold"
    
    # Test case 2
    print(tweakLetters("many", [0, 0, 0, -1]))  # "manx"
    
    # Test case 3
    print(tweakLetters("rhino", [1, 1, 1, 1, 1]))  # "sijop"
    
    # Test case 4
    print(tweakLetters("hello", [0, 0, 0, 0, 0]))  # "hello"
    
    # Test case 5
    print(tweakLetters("code", [-1, 1, -1, 1]))  # "bndf"
