
import re
from typing import Optional

MAX_INPUT_LENGTH: int = 10000
VALID_INPUT_PATTERN: re.Pattern = re.compile(r'^[a-z ]*$')


def highest_scoring_word(input_str: Optional[str]) -> str:
    """Find the highest scoring word in a string."""
    # Validate input
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    # Validate length
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError("Input exceeds maximum length")
    
    # Validate input contains only lowercase letters and spaces
    if not VALID_INPUT_PATTERN.match(input_str):
        raise ValueError("Input must contain only lowercase letters and spaces")
    
    trimmed_input = input_str.strip()
    if not trimmed_input:
        return ""
    
    words = trimmed_input.split(' ')
    highest_word: str = ""
    highest_score: int = 0
    
    for word in words:
        if not word:
            continue
        
        score = calculate_score(word)
        if score > highest_score:
            highest_score = score
            highest_word = word
    
    return highest_word


def calculate_score(word: str) -> int:
    """Calculate the score of a word."""
    score: int = 0
    
    for char in word:
        # Validate character is lowercase letter
        if 'a' <= char <= 'z':
            score += (ord(char) - ord('a') + 1)
    
    return score


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", highest_scoring_word("man i need a taxi up to ubud"))
    
    # Test case 2
    print("Test 2:", highest_scoring_word("what time are we climbing up the volcano"))
    
    # Test case 3
    print("Test 3:", highest_scoring_word("take me to semynak"))
    
    # Test case 4
    print("Test 4:", highest_scoring_word("aa b"))
    
    # Test case 5
    print("Test 5:", highest_scoring_word("a z ba"))
