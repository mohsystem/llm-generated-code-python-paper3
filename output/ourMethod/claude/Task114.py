
from typing import Optional


def copy_string(source: str) -> str:
    """Copy a string safely"""
    if source is None:
        raise ValueError("Source string cannot be None")
    if not isinstance(source, str):
        raise TypeError("Source must be a string")
    # Strings are immutable in Python, create a new copy
    return str(source)


def concatenate_strings(str1: str, str2: str) -> str:
    """Concatenate strings with validation"""
    if str1 is None or str2 is None:
        raise ValueError("Input strings cannot be None")
    if not isinstance(str1, str) or not isinstance(str2, str):
        raise TypeError("Inputs must be strings")
    if len(str1) > 10000 or len(str2) > 10000:
        raise ValueError("String length exceeds maximum allowed size")
    return str1 + str2


def reverse_string(input_str: str) -> str:
    """Reverse a string safely"""
    if input_str is None:
        raise ValueError("Input string cannot be None")
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    if len(input_str) > 10000:
        raise ValueError("String length exceeds maximum allowed size")
    return input_str[::-1]


def to_upper_case_safe(input_str: str) -> str:
    """Convert to uppercase with validation"""
    if input_str is None:
        raise ValueError("Input string cannot be None")
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    if len(input_str) > 10000:
        raise ValueError("String length exceeds maximum allowed size")
    return input_str.upper()


def substring_safe(input_str: str, start: int, end: int) -> str:
    """Substring with bounds checking"""
    if input_str is None:
        raise ValueError("Input string cannot be None")
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    if not isinstance(start, int) or not isinstance(end, int):
        raise TypeError("Start and end indices must be integers")
    if start < 0 or end < 0 or start > end or end > len(input_str):
        raise ValueError("Invalid substring indices")
    return input_str[start:end]


def main() -> None:
    try:
        # Test case 1: Copy string
        print("Test 1 - Copy String:")
        original1 = "Hello, World!"
        copied = copy_string(original1)
        print(f"Original: {original1}")
        print(f"Copied: {copied}")
        print()
        
        # Test case 2: Concatenate strings
        print("Test 2 - Concatenate Strings:")
        str1 = "Hello, "
        str2 = "Python!"
        concatenated = concatenate_strings(str1, str2)
        print(f"String 1: {str1}")
        print(f"String 2: {str2}")
        print(f"Concatenated: {concatenated}")
        print()
        
        # Test case 3: Reverse string
        print("Test 3 - Reverse String:")
        to_reverse = "Programming"
        reversed_str = reverse_string(to_reverse)
        print(f"Original: {to_reverse}")
        print(f"Reversed: {reversed_str}")
        print()
        
        # Test case 4: Convert to uppercase
        print("Test 4 - To Uppercase:")
        to_lower = "secure coding"
        upper = to_upper_case_safe(to_lower)
        print(f"Original: {to_lower}")
        print(f"Uppercase: {upper}")
        print()
        
        # Test case 5: Substring
        print("Test 5 - Substring:")
        full_string = "Security First"
        sub = substring_safe(full_string, 0, 8)
        print(f"Original: {full_string}")
        print(f"Substring [0-8]: {sub}")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
