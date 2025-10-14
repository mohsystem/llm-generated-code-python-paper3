
def tweak_letters(s, tweaks):
    if s is None or tweaks is None or len(s) != len(tweaks):
        return s
    
    result = []
    
    for i in range(len(s)):
        current_char = s[i]
        tweak = tweaks[i]
        
        # Apply the tweak to the character
        new_char_code = ord(current_char) + tweak
        
        # Handle wrapping for lowercase letters
        if 'a' <= current_char <= 'z':
            if new_char_code > ord('z'):
                new_char_code = ord('a') + (new_char_code - ord('z') - 1)
            elif new_char_code < ord('a'):
                new_char_code = ord('z') - (ord('a') - new_char_code - 1)
        
        result.append(chr(new_char_code))
    
    return ''.join(result)


if __name__ == "__main__":
    # Test case 1
    print(tweak_letters("apple", [0, 1, -1, 0, -1]))
    # Expected: "aqold"
    
    # Test case 2
    print(tweak_letters("many", [0, 0, 0, -1]))
    # Expected: "manx"
    
    # Test case 3
    print(tweak_letters("rhino", [1, 1, 1, 1, 1]))
    # Expected: "sijop"
    
    # Test case 4
    print(tweak_letters("zebra", [1, 0, 0, 0, -1]))
    # Expected: "zebrq"
    
    # Test case 5
    print(tweak_letters("hello", [0, 0, 0, 0, 0]))
    # Expected: "hello"
