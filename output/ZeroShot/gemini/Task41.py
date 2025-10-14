def process_string(input_str: str):
    """
    Processes a string. Python's built-in string handling is memory-safe,
    as the interpreter manages memory allocation automatically. This prevents
    buffer overflow vulnerabilities.
    
    :param input_str: The string to be processed.
    """
    print(f'Processing input: "{input_str}"')
    # Python's string operations are safe from buffer overflows.
    processed_string = f'Processed: {input_str.upper()}'
    print(f'Output: "{processed_string}"')
    print("------------------------------------")


def run_tests():
    print("--- Python Test Cases ---")
    
    # Test Case 1: A normal, short string
    process_string("Hello World")

    # Test Case 2: An empty string
    process_string("")

    # Test Case 3: A string with various special characters
    process_string("!@#$%^&*()_+-=[]{}|;':,./<>?")

    # Test Case 4: A very long string
    process_string("This is a very long string that in a language like C could potentially cause a buffer overflow if not handled carefully. In Python, the str object will simply resize to accommodate the data.")

    # Test Case 5: A string with Unicode characters
    process_string("Secure Code (安全なコード)")

# The main execution block
if __name__ == "__main__":
    run_tests()