def to_jaden_case(phrase: str) -> str:
    """
    Converts a string to Jaden Case.

    Args:
        phrase: The string to convert.

    Returns:
        The Jaden-Cased string.
    """
    if not isinstance(phrase, str):
        return "" # Or raise an error, returning empty for simplicity

    if not phrase:
        return ""

    char_list = list(phrase)
    capitalize_next = True

    for i, char in enumerate(char_list):
        if char.isspace():
            capitalize_next = True
        elif capitalize_next and char.isalpha():
            char_list[i] = char.upper()
            capitalize_next = False
    
    return "".join(char_list)

if __name__ == '__main__':
    test_cases = [
        "How can mirrors be real if our eyes aren't real",
        "most trees are blue",
        "",
        "the quick brown fox jumps over the lazy dog.",
        "a string   with   multiple   spaces"
    ]
    
    print("Python Test Cases:")
    for test in test_cases:
        result = to_jaden_case(test)
        print(f"Original: \"{test}\"")
        print(f"Jaden-Cased: \"{result}\"\n")