
def reverse_string(input_str):
    """\n    Reverses a given string safely\n    :param input_str: the string to reverse\n    :return: the reversed string, or empty string if input is None\n    """
    # Security: Handle None input to prevent TypeError
    if input_str is None:
        return ""
    
    # Security: Validate input type
    if not isinstance(input_str, str):
        return ""
    
    # Python strings are immutable, slicing is safe and efficient
    return input_str[::-1]


def main():
    """Main function with test cases"""
    # Test cases
    print("Test Case 1:")
    test1 = "hello"
    print(f"Input: {test1}")
    print(f"Output: {reverse_string(test1)}")
    print()
    
    print("Test Case 2:")
    test2 = "Java Programming"
    print(f"Input: {test2}")
    print(f"Output: {reverse_string(test2)}")
    print()
    
    print("Test Case 3:")
    test3 = "12345"
    print(f"Input: {test3}")
    print(f"Output: {reverse_string(test3)}")
    print()
    
    print("Test Case 4:")
    test4 = ""
    print("Input: (empty string)")
    print(f"Output: {reverse_string(test4)}")
    print()
    
    print("Test Case 5:")
    test5 = None
    print("Input: None")
    print(f"Output: {reverse_string(test5)}")


if __name__ == "__main__":
    main()
