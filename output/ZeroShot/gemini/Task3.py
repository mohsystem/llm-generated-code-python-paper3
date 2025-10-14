import string

def is_pangram(sentence: str) -> bool:
    """
    Checks if a string is a pangram.
    A pangram is a sentence containing every letter of the alphabet at least once.
    This function is case-insensitive and ignores numbers and punctuation.
    
    Args:
        sentence: The string to check.
    
    Returns:
        True if the string is a pangram, False otherwise.
    """
    if not isinstance(sentence, str):
        return False
        
    # Create a set of all lowercase alphabet letters
    required_letters = set(string.ascii_lowercase)
    
    # Create a set of the letters present in the input sentence
    letters_in_sentence = set(sentence.lower())
    
    # A pangram exists if the set of required letters is a subset of
    # the letters found in the sentence.
    return required_letters.issubset(letters_in_sentence)

# Main block for demonstration
if __name__ == '__main__':
    test_cases = [
        "The quick brown fox jumps over the lazy dog",
        "Pack my box with five dozen liquor jugs.",
        "This is not a pangram",
        "Abcdefghijklmnopqrstuvwxyz123!@#",
        ""
    ]

    for i, test_str in enumerate(test_cases, 1):
        print(f"Test Case {i}: \"{test_str}\"")
        print(f"Is Pangram? {is_pangram(test_str)}\n")