
def tweak_letters(s, tweaks):
    # Input validation
    if s is None or tweaks is None:
        return ""
    
    if not s:
        return ""
    
    # Ensure arrays have matching lengths
    length = min(len(s), len(tweaks))
    result = []
    
    for i in range(length):
        c = s[i]
        tweak = tweaks[i]
        
        # Validate tweak value is within safe range
        if tweak < -25 or tweak > 25:
            result.append(c)
            continue
        
        # Only process lowercase letters
        if 'a' <= c <= 'z':
            # Calculate new character with wrapping
            offset = ord(c) - ord('a')
            new_offset = (offset + tweak) % 26
            result.append(chr(ord('a') + new_offset))
        else:
            # Non-lowercase letters remain unchanged
            result.append(c)
    
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
    print(tweak_letters("zebra", [1, -1, 0, 1, -1]))
    # Expected: "aabrz"
    
    # Test case 5
    print(tweak_letters("code", [-1, 1, -1, 1]))
    # Expected: "bpcf"
