def high(s):
    """
    Given a string of words, find the highest scoring word.
    Each letter's score is its position in the alphabet: a=1, b=2, etc.
    If two words score the same, return the one that appears first.
    """
    highest_score = 0
    highest_scoring_word = ""

    for word in s.split(' '):
        current_score = sum(ord(char) - 96 for char in word)
        if current_score > highest_score:
            highest_score = current_score
            highest_scoring_word = word
            
    return highest_scoring_word

if __name__ == '__main__':
    test_cases = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "bb d",
        "d bb"
    ]

    for test in test_cases:
        print(f"Input: \"{test}\"")
        print(f"Output: \"{high(test)}\"\n")