def handle_input(input_str, buffer_size):
    """
    Securely handles user input for a fixed-size buffer.
    In Python, strings are immutable and lists are dynamic, so classic buffer
    overflows don't occur. This function demonstrates secure practice by
    truncating the input to the specified buffer size.

    :param input_str: The user-provided string.
    :param buffer_size: The maximum size of the buffer.
    :return: The potentially truncated string.
    """
    if not isinstance(input_str, str) or buffer_size <= 0:
        return ""
    # Slicing naturally handles strings shorter than the slice length
    # and truncates longer ones. This is a safe and Pythonic way.
    return input_str[:buffer_size]

def main():
    """Main function with test cases."""
    BUFFER_SIZE = 16

    test_inputs = [
        "Short string",      # Case 1: Shorter than buffer
        "Exactly 16 chars",  # Case 2: Exactly buffer size
        "This is a very long string that will be truncated", # Case 3: Longer than buffer
        "",                  # Case 4: Empty string
        "Fifteen chars!!",   # Case 5: One less than buffer size
    ]
    
    print("Python Test Cases (Buffer Size: {})".format(BUFFER_SIZE))
    print("------------------------------------")
    for i, original in enumerate(test_inputs):
        processed = handle_input(original, BUFFER_SIZE)
        print("Test Case {}:".format(i + 1))
        print("  Original:  \"{}\" (length: {})".format(original, len(original)))
        print("  Processed: \"{}\" (length: {})".format(processed, len(processed)))
        print()

if __name__ == "__main__":
    main()