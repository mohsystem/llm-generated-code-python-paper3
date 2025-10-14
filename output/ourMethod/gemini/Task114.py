from typing import Optional

def safe_string_copy(source: str) -> str:
    """
    Creates a copy of a string.
    In Python, strings are immutable. This function returns a new string
    object with the same value, although for immutable types, returning
    the same object is also safe.
    """
    return str(source)

def safe_string_concat(s1: Optional[str], s2: Optional[str]) -> str:
    """
    Safely concatenates two strings, handling None inputs.
    Using f-strings or the '+' operator is safe in Python.
    """
    str1 = s1 if s1 is not None else ""
    str2 = s2 if s2 is not None else ""
    return f"{str1}{str2}"

def reverse_string(source: Optional[str]) -> Optional[str]:
    """
    Reverses a given string using slicing.
    Returns None if the input is None.
    """
    if source is None:
        return None
    return source[::-1]

def main():
    """Main function with test cases."""
    print("--- Testing safe_string_copy ---")
    copy_tests = ["hello", "", "a long string example", "another one", "test"]
    for test_str in copy_tests:
        copied = safe_string_copy(test_str)
        print(f'Original: "{test_str}", Copied: "{copied}"')

    print("\n--- Testing safe_string_concat ---")
    concat_tests = [
        ("Hello, ", "World!"),
        ("", "Append this"),
        ("Start with this", ""),
        ("One", None),
        (None, "Two")
    ]
    for s1, s2 in concat_tests:
        result = safe_string_concat(s1, s2)
        s1_repr = 'None' if s1 is None else f'"{s1}"'
        s2_repr = 'None' if s2 is None else f'"{s2}"'
        print(f's1: {s1_repr}, s2: {s2_repr}, Result: "{result}"')

    print("\n--- Testing reverse_string ---")
    reverse_tests = ["abcdef", "12345", "racecar", "a", ""]
    for test_str in reverse_tests:
        reversed_str = reverse_string(test_str)
        print(f'Original: "{test_str}", Reversed: "{reversed_str}"')

if __name__ == "__main__":
    main()