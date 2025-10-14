def highest_scoring_word(s: str) -> str:
    """
    Finds the highest scoring word in a string.
    Each letter's score is its position in the alphabet (a=1, b=2, ...).
    If scores are tied, the word appearing earliest is returned.
    """
    if not s:
        return ""

    def score(word):
        return sum(ord(char) - ord('a') + 1 for char in word)

    return max(s.split(), key=score)

if __name__ == '__main__':
    # Test cases
    test_cases = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
        "b aa"
    ]

    expected_results = [
        "taxi",
        "volcano",
        "semynak",
        "aa",
        "b"
    ]

    for i in range(len(test_cases)):
        result = highest_scoring_word(test_cases[i])
        print(f"Input: \"{test_cases[i]}\"")
        print(f"Output: {result}")
        print(f"Expected: {expected_results[i]}")
        print("--------------------")