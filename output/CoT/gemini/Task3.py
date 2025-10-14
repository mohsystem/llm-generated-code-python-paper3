import string

def is_pangram(s: str) -> bool:
    """
    Checks if a given string is a pangram.
    A pangram is a sentence that contains every single letter of the alphabet at least once.
    The check is case-insensitive and ignores numbers and punctuation.

    :param s: The input string.
    :return: True if the string is a pangram, False otherwise.
    """
    if not isinstance(s, str):
        return False
        
    # Create a set of all lowercase alphabet letters.
    alphabet = set(string.ascii_lowercase)
    
    # Create a set of all unique letters found in the input string (converted to lowercase).
    string_letters = set(char for char in s.lower() if 'a' <= char <= 'z')
    
    # A string is a pangram if the set of its letters is equal to the set of the alphabet.
    return string_letters == alphabet

if __name__ == '__main__':
    test_cases = [
        "The quick brown fox jumps over the lazy dog",
        "This is not a pangram",
        "Pack my box with five dozen liquor jugs.",
        "Cwm fjord bank glyphs vext quiz",
        "A an B b C c"
    ]

    for i, test_case in enumerate(test_cases):
        result = is_pangram(test_case)
        print(f"Test Case {i + 1}: \"{test_case}\"")
        print(f"Is Pangram? {result}")
        print()