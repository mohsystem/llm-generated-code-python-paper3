import sys

def allocate_and_print(size_str: str):
    """
    Allocates a buffer of the specified size and prints its contents.
    Handles parsing, validation, and potential errors.

    :param size_str: The desired buffer size as a string.
    """
    print(f'--- Processing input: "{size_str}" ---')
    try:
        # 1. Parse the string to an integer
        size = int(size_str)

        # 2. Validate the input size
        if size < 0:
            print("Error: Buffer size cannot be negative.")
            return

        print(f"Allocating buffer of size: {size}")

        # 3. Allocate the buffer
        # In Python, bytearray is zero-initialized.
        # A very large size will raise MemoryError.
        buffer = bytearray(size)

        # 4. Print the contents of the buffer
        # Convert to a list of integers for clear printing
        print(f"Buffer contents: {list(buffer)}")

    except ValueError:
        print("Error: Invalid number format. Please provide an integer.")
    except MemoryError:
        print("Error: Failed to allocate buffer. Memory limit exceeded.")
    finally:
        print("--- Finished processing ---\n")


def main():
    """Main function to handle command-line args or run test cases."""
    if len(sys.argv) == 2:
        # Process the command-line argument if provided
        print("Processing command-line argument...")
        allocate_and_print(sys.argv[1])
    else:
        # Run built-in test cases if no command-line argument is given
        print("No command-line argument found. Running test cases...")

        # Test Case 1: Valid positive size
        allocate_and_print("10")

        # Test Case 2: Zero size
        allocate_and_print("0")

        # Test Case 3: Negative size (invalid)
        allocate_and_print("-5")

        # Test Case 4: Non-numeric input (invalid)
        allocate_and_print("hello")

        # Test Case 5: Large size (may cause MemoryError)
        allocate_and_print("2000000000") # 2 GB

if __name__ == "__main__":
    main()