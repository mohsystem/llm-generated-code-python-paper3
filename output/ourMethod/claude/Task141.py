
from typing import Optional

MAX_INPUT_LENGTH: int = 10000

def reverse_string(input_str: str) -> str:
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds maximum length of {MAX_INPUT_LENGTH}")
    
    return input_str[::-1]

def main() -> None:
    test_cases: list[str] = [
        "hello",
        "world",
        "12345",
        "a",
        "racecar"
    ]
    
    for test_case in test_cases:
        try:
            result: str = reverse_string(test_case)
            print(f'Input: "{test_case}" -> Output: "{result}"')
        except (ValueError, TypeError) as e:
            print(f"Error: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
