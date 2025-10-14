def process_string(input_str):
    """
    Processes a string by printing it and its length.
    Python's built-in string type is dynamically sized and its standard
    input functions are memory-safe, protecting against buffer overflows.
    """
    print(f"Processed String: {input_str}")
    print(f"Length: {len(input_str)}")
    print("--------------------")

def main():
    """Main function to run test cases."""
    print("--- Running Python Test Cases ---")

    # Test Case 1: Regular string
    process_string("Hello, World!")

    # Test Case 2: Another typical string
    process_string("This is a test string.")

    # Test Case 3: Empty string
    process_string("")

    # Test Case 4: A very long string
    process_string("This is a very long string to demonstrate that Python's str type handles memory dynamically, so there is no fixed buffer to overflow unlike in languages like C.")

    # Test Case 5: String with special characters
    process_string("!@#$%^&*()_+-=[]{}|;:'\",.<>?`~")

    print("--- End of Test Cases ---")

if __name__ == "__main__":
    main()