import sys

def string_copy(source: str) -> str:
    """
    Creates a copy of a string. In Python, strings are immutable,
    so simple assignment is safe and efficient. This function
    demonstrates the concept.
    """
    if not isinstance(source, str):
        return None
    return source[:]

def string_concat(s1: str, s2: str) -> str:
    """
    Concatenates two strings securely.
    """
    s1 = "" if s1 is None else s1
    s2 = "" if s2 is None else s2
    if not isinstance(s1, str) or not isinstance(s2, str):
        return None
    return s1 + s2

def string_reverse(source: str) -> str:
    """
    Reverses a string using slicing, which is safe and idiomatic in Python.
    """
    if not isinstance(source, str):
        return None
    return source[::-1]

def main():
    """Main function with test cases."""
    # Test Case 1: Basic operations
    print("--- Test Case 1: Basic Operations ---")
    str1 = "hello"
    str2 = "world"

    copied_str = string_copy(str1)
    print(f"Original: {str1}, Copied: {copied_str}")

    concatenated_str = string_concat(str1, str2)
    print(f'Concatenated: "{str1}" + "{str2}" = "{concatenated_str}"')

    reversed_str = string_reverse("Python")
    print(f"Original: Python, Reversed: {reversed_str}\n")

    # Test Case 2: Empty strings
    print("--- Test Case 2: Empty Strings ---")
    empty_str = ""
    text_str = "test"

    copied_str = string_copy(empty_str)
    print(f'Original: "", Copied: "{copied_str}"')

    concatenated_str = string_concat(empty_str, text_str)
    print(f'Concatenated: "" + "{text_str}" = "{concatenated_str}"')

    reversed_str = string_reverse(empty_str)
    print(f'Original: "", Reversed: "{reversed_str}"\n')

    # Test Case 3: None (null) inputs
    print("--- Test Case 3: None Inputs ---")
    copied_str = string_copy(None) # type: ignore
    print(f"Copying None: {copied_str}")
    concatenated_str = string_concat(None, "safe") # type: ignore
    print(f'Concatenating None and "safe": "{concatenated_str}"')
    reversed_str = string_reverse(None) # type: ignore
    print(f"Reversing None: {reversed_str}\n")
    
    # Test Case 4: Strings with spaces and special characters
    print("--- Test Case 4: Special Characters ---")
    special_str = " A B C!@#123 "
    copied_str = string_copy(special_str)
    print(f'Original: "{special_str}", Copied: "{copied_str}"')

    concatenated_str = string_concat(special_str, "end")
    print(f'Concatenated: "{special_str}" + "end" = "{concatenated_str}"')

    reversed_str = string_reverse(special_str)
    print(f'Original: "{special_str}", Reversed: "{reversed_str}"\n')

    # Test Case 5: Single character string
    print("--- Test Case 5: Single Character String ---")
    single_char_str = "a"
    copied_str = string_copy(single_char_str)
    print(f"Original: {single_char_str}, Copied: {copied_str}")

    concatenated_str = string_concat(single_char_str, "b")
    print(f'Concatenated: "{single_char_str}" + "b" = "{concatenated_str}"')

    reversed_str = string_reverse(single_char_str)
    print(f"Original: {single_char_str}, Reversed: {reversed_str}")

if __name__ == "__main__":
    main()