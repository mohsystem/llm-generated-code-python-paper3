def handle_input(input_str, buffer_size):
    """
    Simulates writing an input string to a fixed-size buffer by truncating it.
    """
    if buffer_size < 0:
        buffer_size = 0
    return input_str[:buffer_size]

if __name__ == "__main__":
    BUFFER_SIZE = 16
    test_cases = [
        "Hello World",
        "This is a long string that will be truncated",
        "1234567890123456", # Exactly 16 characters
        "",
        "Another long test for truncation"
    ]

    for test in test_cases:
        result = handle_input(test, BUFFER_SIZE)
        print(f'Input:  "{test}"')
        print(f'Output: "{result}"\n')