def is_pangram(sentence):
    """
    Checks if a given string is a pangram.
    A pangram is a sentence containing every letter of the English alphabet at least once.
    The check is case-insensitive and ignores numbers and punctuation.

    :param sentence: The input string.
    :return: True if the string is a pangram, False otherwise.
    """
    seen_letters = set()
    for char in sentence.lower():
        if 'a' <= char <= 'z':
            seen_letters.add(char)
    
    return len(seen_letters) == 26

if __name__ == "__main__":
    test_cases = [
        "The quick brown fox jumps over the lazy dog",
        "Pack my box with five dozen liquor jugs.",
        "This is not a pangram",
        "The quick brown fox jumps over the lazy do",
        ""
    ]
    
    print("Running Python Test Cases:")
    for test in test_cases:
        print(f'Input: "{test}"')
        print(f'Is Pangram: {is_pangram(test)}\n')