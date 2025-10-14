
import sys
from typing import Optional

MAX_INPUT_LENGTH = 1024

def process_string(input_str: Optional[str]) -> str:
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds maximum length of {MAX_INPUT_LENGTH}")
    
    byte_size = len(input_str.encode('utf-8'))
    if byte_size > MAX_INPUT_LENGTH:
        raise ValueError("Input byte size exceeds maximum length")
    
    processed = []
    for char in input_str:
        if char.isalnum() or char.isspace() or char in '.,!?':
            processed.append(char)
    
    return ''.join(processed)

def main() -> None:
    test_cases = [
        "Hello World",
        "Test123 with numbers!",
        "Special chars: @#$%^&*()",
        "A" * 100,
        ""
    ]
    
    print("Running test cases:")
    for i, test_input in enumerate(test_cases, 1):
        try:
            result = process_string(test_input)
            print(f"Test {i}: Success")
            print(f"  Input: {test_input[:50]}")
            print(f"  Output: {result[:50]}")
        except Exception as e:
            print(f"Test {i}: Error - {e}")

if __name__ == "__main__":
    main()
