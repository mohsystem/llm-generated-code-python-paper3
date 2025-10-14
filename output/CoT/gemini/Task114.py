def copy_string(source: str) -> str:
    """
    Creates a copy of the given string.
    Since strings are immutable in Python, assignment is sufficient.
    Slicing creates a new shallow copy.
    """
    if source is None:
        return None
    return source[:]

def concatenate_strings(s1: str, s2: str) -> str:
    """
    Concatenates two strings.
    """
    s1 = s1 or ""
    s2 = s2 or ""
    return s1 + s2

def get_string_length(s: str) -> int:
    """
    Gets the length of a string.
    """
    if s is None:
        return 0
    return len(s)

def find_substring(main_str: str, sub_str: str) -> int:
    """
    Finds the first occurrence of a substring within a main string.
    Returns the starting index or -1 if not found.
    """
    if main_str is None or sub_str is None:
        return -1
    return main_str.find(sub_str)

def replace_substring(main_str: str, old_sub: str, new_sub: str) -> str:
    """
    Replaces all occurrences of a substring with a new substring.
    """
    if main_str is None or old_sub is None or new_sub is None:
        return main_str
    return main_str.replace(old_sub, new_sub)

if __name__ == "__main__":
    # Test Case 1: Copying a string
    original1 = "Hello World"
    copied1 = copy_string(original1)
    print("Test Case 1: Copying a String")
    print(f'Original:  "{original1}"')
    print(f'Copied:    "{copied1}"\n')

    # Test Case 2: Concatenating strings
    s1 = "Hello, "
    s2 = "World!"
    concatenated = concatenate_strings(s1, s2)
    print("Test Case 2: Concatenating Strings")
    print(f'String 1: "{s1}"')
    print(f'String 2: "{s2}"')
    print(f'Concatenated: "{concatenated}"\n')

    # Test Case 3: Getting string length
    s3 = "Programming"
    length = get_string_length(s3)
    print("Test Case 3: Getting String Length")
    print(f'String: "{s3}"')
    print(f'Length: {length}\n')

    # Test Case 4: Finding a substring
    main_str4 = "This is a test"
    sub_str4 = "is"
    index = find_substring(main_str4, sub_str4)
    print("Test Case 4: Finding a Substring")
    print(f'Main String: "{main_str4}"')
    print(f'Substring:   "{sub_str4}"')
    print(f'Found at index: {index}\n')

    # Test Case 5: Replacing a substring
    main_str5 = "The house is blue and the car is blue."
    old_sub5 = "blue"
    new_sub5 = "red"
    replaced = replace_substring(main_str5, old_sub5, new_sub5)
    print("Test Case 5: Replacing a Substring")
    print(f'Original: "{main_str5}"')
    print(f'Replaced: "{replaced}"\n')