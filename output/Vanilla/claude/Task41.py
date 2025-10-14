
def process_string(input_str):
    """\n    Process a string input safely.\n    Python strings are immutable and dynamically sized,\n    so buffer overflow is not possible.\n    """
    if input_str is None:
        return "Error: Input is None"
    
    # Python automatically handles memory management
    return f"Processed: {input_str}"


def main():
    # Test case 1: Normal string
    print("Test 1:", process_string("Hello World"))
    
    # Test case 2: Empty string
    print("Test 2:", process_string(""))
    
    # Test case 3: Very long string
    long_string = "a" * 10000
    result = process_string(long_string)
    print("Test 3:", result[:50] + "...")
    
    # Test case 4: Special characters
    print("Test 4:", process_string("!@#$%^&*()_+-=[]{}|;':,.<>?"))
    
    # Test case 5: None input
    print("Test 5:", process_string(None))


if __name__ == "__main__":
    main()
