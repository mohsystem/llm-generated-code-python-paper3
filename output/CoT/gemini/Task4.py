def is_isogram(string: str) -> bool:
    """
    Determines whether a string is an isogram (has no repeating letters, ignoring case).

    :param string: The input string, assumed to contain only letters.
    :return: True if the string is an isogram, False otherwise.
    """
    # An empty string is considered an isogram.
    if not string:
        return True

    # Convert to a single case to make comparisons case-insensitive.
    lower_string = string.lower()

    # Use a set to efficiently track seen characters.
    seen = set()
    for char in lower_string:
        # If the character is already in the set, it's a repeat.
        if char in seen:
            return False
        # Otherwise, add it to the set.
        seen.add(char)

    # If the loop completes, no repeating characters were found.
    return True

# A more "Pythonic" one-liner alternative:
# def is_isogram(string: str) -> bool:
#     lower_string = string.lower()
#     return len(lower_string) == len(set(lower_string))

if __name__ == '__main__':
    # Test cases
    test_cases = {
        "Dermatoglyphics": True,
        "aba": False,
        "moOse": False,
        "isIsogram": False,
        "": True
    }

    for text, expected in test_cases.items():
        result = is_isogram(text)
        print(f'Input: "{text}" -> Output: {result} | Expected: {expected}')