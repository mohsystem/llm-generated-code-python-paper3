def is_pangram(input_str: str) -> bool:
    """
    Check if a string is a pangram (contains all 26 letters of the alphabet).

    Args:
        input_str: The string to check

    Returns:
        True if the string is a pangram, False otherwise
    """
    # Validate input
    if input_str is None:
        return False

    if not isinstance(input_str, str):
        return False

    # Track unique letters seen
    letters = set()

    for char in input_str:
        # Convert to lowercase and check if it's a letter
        if 'A' <= char <= 'Z':
            letters.add(chr(ord(char) + 32))  # Convert to lowercase
        elif 'a' <= char <= 'z':
            letters.add(char)

    # A pangram must contain all 26 letters
    return len(letters) == 26


if __name__ == "__main__":
    # Test case 1: Classic pangram
    test1 = "The quick brown fox jumps over the lazy dog"
    print(f'Test 1: "{test1}" -> {is_pangram(test1)}')

    # Test case 2: Pangram with numbers and punctuation
    test2 = "Pack my box with five dozen liquor jugs!!! 123"
    print(f'Test 2: "{test2}" -> {is_pangram(test2)}')

    # Test case 3: Not a pangram
    test3 = "This is not a pangram"
    print(f'Test 3: "{test3}" -> {is_pangram(test3)}')

    # Test case 4: Empty string
    test4 = ""
    print(f'Test 4: "{test4}" -> {is_pangram(test4)}')

    # Test case 5: All letters present with special characters
    test5 = "abcdefghijklmnopqrstuvwxyz!@#$%^&*()"
    print(f'Test 5: "{test5}" -> {is_pangram(test5)}')
