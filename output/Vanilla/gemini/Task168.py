def tweak_letters(s, tweaks):
    """
    Tweaks letters by one forward (+1) or backwards (-1) according to a list.
    
    :param s: The input string of lowercase letters.
    :param tweaks: A list of integers (0, 1, or -1).
    :return: The tweaked string.
    """
    if len(s) != len(tweaks):
        return "" # Or raise an error
        
    result = []
    for i in range(len(s)):
        char_code = ord(s[i]) + tweaks[i]
        
        if char_code > ord('z'):
            result.append('a')
        elif char_code < ord('a'):
            result.append('z')
        else:
            result.append(chr(char_code))
            
    return "".join(result)

if __name__ == '__main__':
    # Test Case 1
    print(tweak_letters("apple", [0, 1, -1, 0, -1]))
    
    # Test Case 2
    print(tweak_letters("many", [0, 0, 0, -1]))
    
    # Test Case 3
    print(tweak_letters("rhino", [1, 1, 1, 1, 1]))
    
    # Test Case 4
    print(tweak_letters("zebra", [1, -1, 1, -1, 1]))
    
    # Test Case 5
    print(tweak_letters("abc", [-1, 0, 1]))