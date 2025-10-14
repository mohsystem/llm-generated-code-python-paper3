def highest_scoring_word(s: str) -> str:
    """
    Given a string of words, find the highest scoring word.
    Each letter's score is its position in the alphabet (a=1, b=2, ...).
    If two words score the same, return the one that appears first.
    """
    if not s:
        return ""

    words = s.split(' ')
    max_score = -1
    highest_word = ""

    for word in words:
        # ord(c) - 96 gives the score for lowercase letters a-z
        current_score = sum(ord(c) - 96 for c in word)
        if current_score > max_score:
            max_score = current_score
            highest_word = word
            
    return highest_word

if __name__ == "__main__":
    test_cases = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aaa b",
        "b aa"
    ]
    
    print("Running Python Test Cases:")
    for i, test in enumerate(test_cases):
        result = highest_scoring_word(test)
        print(f"Test Case {i + 1}: \"{test}\"")
        print(f"Result: {result}")
        print("--------------------")