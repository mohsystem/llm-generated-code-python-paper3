
import re
from typing import Optional

MAX_INPUT_LENGTH: int = 1000
ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\\s]+$')
NUMERIC_PATTERN = re.compile(r'^-?\\d+$')


def validate_and_process_string(input_str: Optional[str]) -> str:
    """Validates and processes a string input."""
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if len(input_str) == 0:
        raise ValueError("Input cannot be empty")
    
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds maximum length of {MAX_INPUT_LENGTH}")
    
    if not ALPHANUMERIC_PATTERN.match(input_str):
        raise ValueError("Input contains invalid characters. Only alphanumeric characters and spaces are allowed")
    
    trimmed = input_str.strip()
    result = trimmed.upper()
    return result


def validate_and_process_number(input_str: Optional[str]) -> int:
    """Validates and processes a numeric input."""
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    trimmed = input_str.strip()
    
    if len(trimmed) == 0:
        raise ValueError("Input cannot be empty")
    
    if not NUMERIC_PATTERN.match(trimmed):
        raise ValueError("Input is not a valid integer")
    
    try:
        number = int(trimmed)
        
        if number < -1000000 or number > 1000000:
            raise ValueError("Number must be between -1000000 and 1000000")
        
        return number * 2
    except (ValueError, OverflowError) as e:
        raise ValueError("Input is not a valid integer or out of range") from e


def concatenate_validated_strings(input1: Optional[str], input2: Optional[str]) -> str:
    """Concatenates two validated strings."""
    validated1 = validate_and_process_string(input1)
    validated2 = validate_and_process_string(input2)
    
    if len(validated1) + len(validated2) + 1 > MAX_INPUT_LENGTH:
        raise ValueError("Combined length exceeds maximum allowed")
    
    return validated1 + " " + validated2


def main() -> None:
    """Test cases for input validation functions."""
    print("Test Case 1: Valid alphanumeric string")
    try:
        result1 = validate_and_process_string("Hello World 123")
        print(f"Result: {result1}")
    except ValueError as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 2: Valid number")
    try:
        result2 = validate_and_process_number("42")
        print(f"Result: {result2}")
    except ValueError as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 3: Invalid string with special characters")
    try:
        result3 = validate_and_process_string("Hello@World!")
        print(f"Result: {result3}")
    except ValueError as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 4: Invalid number")
    try:
        result4 = validate_and_process_number("not a number")
        print(f"Result: {result4}")
    except ValueError as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 5: Concatenate two valid strings")
    try:
        result5 = concatenate_validated_strings("Test 123", "Data 456")
        print(f"Result: {result5}")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
