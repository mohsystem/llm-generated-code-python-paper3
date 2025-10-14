
from typing import List

def tweak_letters(s: str, tweaks: List[int]) -> str:
    # Validate inputs
    if s is None or tweaks is None:
        raise ValueError("Input string and tweaks list cannot be None")
    
    if len(s) == 0:
        return s
    
    if len(s) != len(tweaks):
        raise ValueError("String length must match tweaks list length")
    
    # Validate string contains only letters
    if not all(c.isalpha() for c in s):
        raise ValueError("String must contain only letters")
    
    # Validate tweaks list contains only -1, 0, or 1
    if not all(t in (-1, 0, 1) for t in tweaks):
        raise ValueError("Tweaks must be -1, 0, or 1")
    
    result = []
    
    for i in range(len(s)):
        c = s[i].lower()
        tweak = tweaks[i]
        
        # Apply tweak with wrapping
        char_value = ord(c) - ord('a')
        char_value = (char_value + tweak) % 26
        tweaked_char = chr(ord('a') + char_value)
        
        result.append(tweaked_char)
    
    return ''.join(result)


if __name__ == "__main__":
    # Test case 1
    result1 = tweak_letters("apple", [0, 1, -1, 0, -1])
    print(f"Test 1: {result1} (expected: aqold)")
    
    # Test case 2
    result2 = tweak_letters("many", [0, 0, 0, -1])
    print(f"Test 2: {result2} (expected: manx)")
    
    # Test case 3
    result3 = tweak_letters("rhino", [1, 1, 1, 1, 1])
    print(f"Test 3: {result3} (expected: sijop)")
    
    # Test case 4
    result4 = tweak_letters("zebra", [1, 0, 0, 0, -1])
    print(f"Test 4: {result4} (expected: aebrq)")
    
    # Test case 5
    result5 = tweak_letters("code", [-1, -1, -1, -1])
    print(f"Test 5: {result5} (expected: bncd)")
