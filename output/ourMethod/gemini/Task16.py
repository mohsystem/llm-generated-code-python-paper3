from typing import Text

def solution(text: str, ending: str) -> bool:
    """
    Checks if the first string ends with the second string.

    Args:
        text: The main string.
        ending: The potential ending string.

    Returns:
        True if text ends with ending, False otherwise.
    """
    if not isinstance(text, str) or not isinstance(ending, str):
        return False
    return text.endswith(ending)

if __name__ == '__main__':
    # Test Case 1: Standard true case
    print(f"Test 1: solution('abc', 'bc') -> {solution('abc', 'bc')}") # Expected: True

    # Test Case 2: Standard false case
    print(f"Test 2: solution('abc', 'd') -> {solution('abc', 'd')}") # Expected: False
    
    # Test Case 3: Ending is the same as the string
    print(f"Test 3: solution('samantha', 'samantha') -> {solution('samantha', 'samantha')}") # Expected: True
    
    # Test Case 4: Ending is an empty string
    print(f"Test 4: solution('abc', '') -> {solution('abc', '')}") # Expected: True
    
    # Test Case 5: Main string is shorter than the ending
    print(f"Test 5: solution('a', 'abc') -> {solution('a', 'abc')}") # Expected: False