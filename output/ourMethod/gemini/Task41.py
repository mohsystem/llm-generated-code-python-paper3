import typing

def process_string(input_str: str) -> str:
    """
    Processes a string by creating a safe copy of it.
    In Python, strings are immutable and memory is managed automatically,
    which inherently protects against buffer overflow vulnerabilities.

    Args:
        input_str: The string to be processed.

    Returns:
        A new string object that is a copy of the input.
    """
    if not isinstance(input_str, str):
        return ""
    # String slicing creates a copy. This is an inherently safe operation.
    # This simulates copying to a new "buffer" without any overflow risk.
    return input_str[:]

def main():
    """Main function with test cases."""
    # --- Test Cases ---
    test_cases = [
        "Hello, World!",
        "",
        "This is a slightly longer string to test processing.",
        "A string with special characters: !@#$%^&*()_+",
        "A very long string to ensure that there are no issues with larger inputs. "
        "Python's string handling is dynamic and not prone to classic buffer overflows."
    ]

    print("--- Running Test Cases ---")
    for i, test_str in enumerate(test_cases):
        print(f"\nTest Case {i + 1}:")
        print(f"Original:  \"{test_str}\"")
        processed = process_string(test_str)
        print(f"Processed: \"{processed}\"")

    # Example with user input
    try:
        print("\n--- User Input Test ---")
        # The input() function safely reads a line from stdin.
        user_input = input("Enter a string to process: ")
        processed_user_input = process_string(user_input)
        print(f"Processed user input: \"{processed_user_input}\"")
    except EOFError:
        print("\nNo input provided.")


if __name__ == "__main__":
    main()