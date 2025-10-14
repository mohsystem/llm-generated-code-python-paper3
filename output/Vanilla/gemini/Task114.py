def copy_string(s):
    """Creates a copy of a string."""
    return str(s)

def concatenate_strings(s1, s2):
    """Concatenates two strings."""
    return s1 + s2

def get_string_length(s):
    """Gets the length of a string."""
    return len(s)

def find_substring(main_str, sub_str):
    """Finds the index of a substring within a main string."""
    return main_str.find(sub_str)

def to_upper_case(s):
    """Converts a string to uppercase."""
    return s.upper()

def to_lower_case(s):
    """Converts a string to lowercase."""
    return s.lower()

def main():
    """Main function with test cases."""
    test_cases = [
        ("Hello", "World"),
        ("Python", "Scripting"),
        ("Test", "Case"),
        ("one two three", "two"),
        ("UPPER", "lower")
    ]

    for i, (s1, s2) in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Original strings: \"{s1}\", \"{s2}\"")

        # Copy
        copied = copy_string(s1)
        print(f"Copied s1: {copied}")

        # Concatenate
        concatenated = concatenate_strings(s1, s2)
        print(f"Concatenated: {concatenated}")

        # Length
        print(f"Length of s1: {get_string_length(s1)}")

        # Find Substring
        if s1 == "one two three" and s2 == "two": # special case for test 4
            index = find_substring(s1, s2)
            print(f"Index of \"{s2}\" in \"{s1}\": {index}")
        else:
            index = find_substring(s1, "o")
            print(f"Index of 'o' in \"{s1}\": {index}")

        # To Uppercase
        print(f"s1 to uppercase: {to_upper_case(s1)}")
        
        # To Lowercase
        print(f"s2 to lowercase: {to_lower_case(s2)}")
        print()

if __name__ == "__main__":
    main()