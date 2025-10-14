from typing import Set

def is_isogram(s: str) -> bool:
    """
    Checks if a string is an isogram (has no repeating letters, case-insensitive).

    Args:
        s: The string to check. Assumed to contain only letters.

    Returns:
        True if the string is an isogram, False otherwise.
    """
    if not isinstance(s, str):
        # Or raise TypeError, depending on desired behavior for invalid input.
        return False
        
    lower_s = s.lower()
    return len(lower_s) == len(set(lower_s))

def main():
    """Main function with test cases."""
    test_cases = {
        "Dermatoglyphics": True,
        "aba": False,
        "moOse": False,
        "isogram": True,
        "": True
    }
    
    for test_str, expected in test_cases.items():
        result = is_isogram(test_str)
        print(f'"{test_str}" --> {str(result).lower()}')
        # assert result == expected # Optional: for automated testing

if __name__ == "__main__":
    main()