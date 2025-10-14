from typing import List

def tweak_letters(s: str, tweaks: List[int]) -> str:
    """
    Tweaks letters in a string by one forward (+1) or backward (-1) according to a list.

    :param s: The input string (assumed to be lowercase letters).
    :param tweaks: A list of integers (0, 1, or -1) of the same length as s.
    :return: A new string with the tweaked letters.
    :raises ValueError: if inputs have mismatched lengths.
    """
    if len(s) != len(tweaks):
        raise ValueError("Input string and tweaks list must have the same length.")
    
    result_chars = []
    for i in range(len(s)):
        original_char_code = ord(s[i])
        tweaked_char_code = original_char_code + tweaks[i]
        result_chars.append(chr(tweaked_char_code))
        
    return "".join(result_chars)

if __name__ == '__main__':
    # Test Case 1
    print(f"Test 1: 'apple', [0, 1, -1, 0, -1] -> {tweak_letters('apple', [0, 1, -1, 0, -1])}")
    
    # Test Case 2
    print(f"Test 2: 'many', [0, 0, 0, -1] -> {tweak_letters('many', [0, 0, 0, -1])}")
    
    # Test Case 3
    print(f"Test 3: 'rhino', [1, 1, 1, 1, 1] -> {tweak_letters('rhino', [1, 1, 1, 1, 1])}")
    
    # Test Case 4: Empty string
    print(f"Test 4: '', [] -> {tweak_letters('', [])}")
    
    # Test Case 5: All zeros
    print(f"Test 5: 'hello', [0, 0, 0, 0, 0] -> {tweak_letters('hello', [0, 0, 0, 0, 0])}")