def is_isogram(string: str) -> bool:
    """
    Determines if a string is an isogram.
    An isogram is a word that has no repeating letters. Case is ignored.
    Assumes the input string contains only letters.
    
    Args:
        string: The string to check.
    
    Returns:
        True if the string is an isogram, False otherwise.
    """
    # Convert string to lowercase to handle case-insensitivity.
    lower_string = string.lower()
    
    # A set stores only unique elements. If the length of the set of characters
    # is the same as the length of the string, all characters are unique.
    return len(lower_string) == len(set(lower_string))

if __name__ == "__main__":
    test_cases = [
        "Dermatoglyphics",
        "aba",
        "moOse",
        "",
        "isogram"
    ]
    
    print("Python Test Cases:")
    for test in test_cases:
        result = is_isogram(test)
        print(f'"{test}" --> {result}')