import typing

def tweak_letters(s: str, tweaks: typing.List[int]) -> str:
    """
    Tweaks letters in a string based on a list of integer shifts.
    
    Args:
        s: The input string.
        tweaks: A list of integers representing the shift for each character.
        
    Returns:
        The tweaked string, or an error message if inputs are invalid.
    """
    if not isinstance(s, str) or not isinstance(tweaks, list) or len(s) != len(tweaks):
        # In idiomatic Python, raising a ValueError would be more appropriate.
        return "Invalid input"
    
    return "".join([chr(ord(char) + tweak) for char, tweak in zip(s, tweaks)])

# main method with 5 test cases
if __name__ == '__main__':
    # Test Case 1
    print(tweak_letters("apple", [0, 1, -1, 0, -1]))
    # Test Case 2
    print(tweak_letters("many", [0, 0, 0, -1]))
    # Test Case 3
    print(tweak_letters("rhino", [1, 1, 1, 1, 1]))
    # Test Case 4
    print(tweak_letters("abc", [-1, 0, 1]))
    # Test Case 5
    print(tweak_letters("z", [1]))