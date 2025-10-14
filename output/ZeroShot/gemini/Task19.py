def spin_words(sentence: str) -> str:
    """
    Reverses words in a sentence that have five or more letters.
    
    :param sentence: The input string containing words and spaces.
    :return: The modified string with long words reversed.
    """
    # split() handles multiple spaces and leading/trailing spaces gracefully
    words = sentence.split()
    spun_words = [word[::-1] if len(word) >= 5 else word for word in words]
    return " ".join(spun_words)

if __name__ == '__main__':
    test_cases = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "Welcome to the jungle",
        "Supercalifragilisticexpialidocious"
    ]
    
    for test in test_cases:
        print(spin_words(test))