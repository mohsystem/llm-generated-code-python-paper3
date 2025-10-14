import re
import datetime
from typing import Final

# Rule #1: Define constants for validation rules.
NAME_PATTERN: Final = re.compile(r"^[a-zA-Z ]{2,50}$")
MIN_AGE: Final = 0
MAX_AGE: Final = 120

def process_user_input(name: str, age_str: str) -> str:
    """
    Validates user name and age, then returns a greeting string or an error message.
    
    Args:
        name: The user's name.
        age_str: The user's age as a string.

    Returns:
        A formatted string with a greeting and calculated birth year, or an error message.
    """
    # Rule #1 & #6: Ensure all input is validated and treated as untrusted.
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        return "Error: Invalid name. Name must be 2-50 letters and spaces."

    # Rule #6: Use safe parsing with try-except for type conversion.
    try:
        age = int(age_str)
        # Rule #1: Validate range.
        if not (MIN_AGE <= age <= MAX_AGE):
            return f"Error: Invalid age. Age must be between {MIN_AGE} and {MAX_AGE}."
    except (ValueError, TypeError):
        # Rule #6: Fail closed with a clear error on parsing failure.
        return "Error: Invalid age format. Please enter a whole number."

    # Operation on validated data
    current_year = datetime.datetime.now().year
    birth_year = current_year - age

    # Rule #6: Use safe formatting (f-strings are safe with validated types).
    # The 'name' variable has been validated against a strict whitelist pattern.
    return f"Hello, {name}! You are {age} years old. You were likely born in {birth_year}."

def main():
    """ Main function with 5 test cases """
    print("--- Running Test Cases ---")

    # Test Case 1: Valid input
    print("Test 1 (Valid):")
    print("Input: name='Alice', age='30'")
    print(f"Output: {process_user_input('Alice', '30')}\n")

    # Test Case 2: Invalid name (too short)
    print("Test 2 (Invalid Name - Length):")
    print("Input: name='J', age='25'")
    print(f"Output: {process_user_input('J', '25')}\n")

    # Test Case 3: Invalid name (contains numbers)
    print("Test 3 (Invalid Name - Chars):")
    print("Input: name='Bob123', age='40'")
    print(f"Output: {process_user_input('Bob123', '40')}\n")

    # Test Case 4: Invalid age (not a number)
    print("Test 4 (Invalid Age - Format):")
    print("Input: name='Charlie', age='twenty'")
    print(f"Output: {process_user_input('Charlie', 'twenty')}\n")

    # Test Case 5: Invalid age (out of range)
    print("Test 5 (Invalid Age - Range):")
    print("Input: name='David', age='150'")
    print(f"Output: {process_user_input('David', '150')}\n")

if __name__ == "__main__":
    main()