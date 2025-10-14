
import re
from typing import Union

MAX_INPUT_LENGTH = 1000
INTEGER_PATTERN = re.compile(r'^-?\\d+$')
DOUBLE_PATTERN = re.compile(r'^-?\\d+\\.?\\d*$')


def process_user_input(input_str: str) -> str:
    """Validate and sanitize user input."""
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds maximum length of {MAX_INPUT_LENGTH}")
    
    trimmed_input = input_str.strip()
    
    if not trimmed_input:
        raise ValueError("Input cannot be empty")
    
    return trimmed_input


def parse_integer(input_str: str) -> int:
    """Parse and validate integer input."""
    processed = process_user_input(input_str)
    
    if not INTEGER_PATTERN.match(processed):
        raise ValueError(f"Invalid integer format: {processed}")
    
    try:
        result = int(processed)
        return result
    except (ValueError, OverflowError) as e:
        raise ValueError(f"Integer out of range: {processed}") from e


def parse_double(input_str: str) -> float:
    """Parse and validate floating-point input."""
    processed = process_user_input(input_str)
    
    if not DOUBLE_PATTERN.match(processed):
        raise ValueError(f"Invalid double format: {processed}")
    
    try:
        result = float(processed)
        if result == float('inf') or result == float('-inf') or result != result:
            raise ValueError(f"Double out of range or invalid: {processed}")
        return result
    except (ValueError, OverflowError) as e:
        raise ValueError(f"Invalid double value: {processed}") from e


def safe_divide(numerator: int, denominator: int) -> int:
    """Perform safe integer division with error checking."""
    if not isinstance(numerator, int) or not isinstance(denominator, int):
        raise TypeError("Both arguments must be integers")
    
    if denominator == 0:
        raise ArithmeticError("Division by zero is not allowed")
    
    # Check for overflow in Python (though Python handles big integers)
    if numerator == -(2**31) and denominator == -1:
        raise ArithmeticError("Integer overflow in division")
    
    return numerator // denominator


def safe_add(a: int, b: int) -> int:
    """Perform safe integer addition with overflow checking."""
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Both arguments must be integers")
    
    # Python handles arbitrary precision, but we simulate 32-bit bounds
    INT_MAX = 2**31 - 1
    INT_MIN = -(2**31)
    
    result = a + b
    if result > INT_MAX or result < INT_MIN:
        raise ArithmeticError("Integer overflow in addition")
    
    return result


def main():
    print("=== Test Case 1: Valid integer parsing ===")
    try:
        result = parse_integer("42")
        print(f"Parsed integer: {result}")
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    
    print("\\n=== Test Case 2: Invalid integer (non-numeric) ===")
    try:
        result = parse_integer("abc")
        print(f"Parsed integer: {result}")
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    
    print("\\n=== Test Case 3: Division by zero ===")
    try:
        result = safe_divide(10, 0)
        print(f"Division result: {result}")
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    
    print("\\n=== Test Case 4: Valid double parsing ===")
    try:
        result = parse_double("3.14159")
        print(f"Parsed double: {result}")
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)
    
    print("\\n=== Test Case 5: Integer overflow protection ===")
    try:
        result = safe_add(2147483647, 1)
        print(f"Addition result: {result}")
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)


if __name__ == "__main__":
    main()
