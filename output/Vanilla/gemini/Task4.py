def is_isogram(string):
    """
    Determines if a string is an isogram (has no repeating letters, case-insensitive).

    Args:
        string: The string to check.
    
    Returns:
        True if the string is an isogram, False otherwise.
    """
    # Convert the string to lowercase to make the check case-insensitive.
    lower_string = string.lower()
    
    # A set contains only unique elements. If the length of the string
    # is the same as the length of the set of its characters,
    # then all characters must be unique.
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
        # Convert boolean True/False to lowercase "true"/"false" for consistent output format.
        result = str(is_isogram(test)).lower()
        print(f'"{test}" --> {result}')