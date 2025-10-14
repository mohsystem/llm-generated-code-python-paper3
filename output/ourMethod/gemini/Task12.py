from typing import List

def highest_scoring_word(s: str) -> str:
    """
    Finds the highest scoring word in a string.
    If scores are tied, the word appearing earliest wins.
    """
    if not s:
        return ""

    def get_score(word: str) -> int:
        """Calculates score for a single word."""
        return sum(ord(char) - ord('a') + 1 for char in word)

    words: List[str] = s.split(' ')
    
    max_score = -1
    highest_word = ""

    for word in words:
        current_score = get_score(word)
        if current_score > max_score:
            max_score = current_score
            highest_word = word
            
    return highest_word

if __name__ == "__main__":
    test_cases = [
        "man i need a taxi up to dublin",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
        "b aa"
    ]
    expected_results = [
        "dublin",
        "volcano",
        "semynak",
        "aa",
        "b"
    ]
    
    for i, test_str in enumerate(test_cases):
        result = highest_scoring_word(test_str)
        print(f'Test Case: "{test_str}"')
        print(f'Expected: {expected_results[i]}')
        print(f'Got: {result}')
        print(f'Result: {"PASS" if result == expected_results[i] else "FAIL"}')
        print()