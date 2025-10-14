def process_string(input_str: str):
    """
    Processes the input string. Python's built-in string type is dynamically
    sized and memory is managed by the Python interpreter, which makes it
    immune to classic buffer overflow attacks.
    
    Args:
        input_str: The string to be processed.
    """
    print(f'Processing input: "{input_str}"')
    print(f"Length: {len(input_str)}")
    # In a real application, further safe processing would occur here.
    print("Processing complete.")
    print("----------------------------------------")


def main():
    """ Main function with 5 test cases """
    print("--- Python Test Cases (Buffer Overflow Safe by Design) ---")
    
    # Test Case 1: A typical short string
    process_string("Hello, World!")
    
    # Test Case 2: An empty string
    process_string("")
    
    # Test Case 3: A long string
    process_string("This is a very long string designed to test the dynamic memory allocation of Python's str type, which prevents buffer overflows automatically.")
    
    # Test Case 4: A string with special characters and unicode
    process_string("!@#$%^&*()_+-={}[]|;'<>,.?/`~ \u20AC")
    
    # Test Case 5: A string with various whitespace characters
    process_string("A string with\ttabs and\nnew lines.")

if __name__ == "__main__":
    main()