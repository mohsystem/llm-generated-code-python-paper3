
import secrets
from typing import Optional

ASCII_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
MAX_LENGTH = 100000

def generate_random_string(length: int) -> str:
    if not isinstance(length, int):
        raise TypeError("Length must be an integer")
    if length < 0:
        raise ValueError("Length must be non-negative")
    if length > MAX_LENGTH:
        raise ValueError(f"Length exceeds maximum allowed: {MAX_LENGTH}")
    if length == 0:
        return ""
    
    result = ''.join(secrets.choice(ASCII_LETTERS) for _ in range(length))
    return result

def main() -> None:
    print(f"Test Case 1 (length=10): {generate_random_string(10)}")
    print(f"Test Case 2 (length=20): {generate_random_string(20)}")
    print(f"Test Case 3 (length=5): {generate_random_string(5)}")
    print(f"Test Case 4 (length=0): {generate_random_string(0)}")
    print(f"Test Case 5 (length=15): {generate_random_string(15)}")

if __name__ == "__main__":
    main()
