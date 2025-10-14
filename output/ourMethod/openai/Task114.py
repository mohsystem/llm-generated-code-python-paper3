from typing import List

MAX_LEN: int = 100_000

def _validate_string(s: str) -> None:
    if not isinstance(s, str):
        raise ValueError("Input must be a string.")
    if len(s) > MAX_LEN:
        raise ValueError("Input string exceeds maximum allowed length.")

def copy_string(s: str) -> str:
    _validate_string(s)
    return s[:]

def concat_strings(a: str, b: str) -> str:
    _validate_string(a)
    _validate_string(b)
    if len(a) + len(b) > MAX_LEN:
        raise ValueError("Concatenated string would exceed maximum allowed length.")
    return a + b

def reverse_string(s: str) -> str:
    _validate_string(s)
    return s[::-1]

def to_upper_case(s: str) -> str:
    _validate_string(s)
    return s.upper()

def safe_substring(s: str, start: int, length: int) -> str:
    _validate_string(s)
    if not isinstance(start, int) or not isinstance(length, int):
        raise ValueError("Start and length must be integers.")
    if start < 0 or length < 0:
        raise ValueError("Start and length must be non-negative.")
    end = start + length
    if end > len(s):
        raise ValueError("Substring range is out of bounds.")
    sub = s[start:end]
    if len(sub) > MAX_LEN:
        raise ValueError("Result exceeds maximum allowed length.")
    return sub

def main() -> None:
    try:
        # Test 1: Copy
        print("Copy:", copy_string("Hello"))
        # Test 2: Concat
        print("Concat:", concat_strings("Hello", " World"))
        # Test 3: Reverse
        print("Reverse:", reverse_string("RaceCar"))
        # Test 4: To Upper
        print("Upper:", to_upper_case("security123"))
        # Test 5: Safe Substring
        print("Substring:", safe_substring("abcdef", 2, 3))
    except ValueError as e:
        print("Error:", str(e))

if __name__ == "__main__":
    main()