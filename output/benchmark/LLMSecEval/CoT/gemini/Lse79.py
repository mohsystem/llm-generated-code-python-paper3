import sys

def perform_allocation_and_read():
    """
    Simulates allocating two large buffers and reading 100 characters
    from stdin into each. In Python, memory is managed automatically
    and strings are dynamic, so we simulate this by reading a fixed
    number of characters.
    """
    # Python's strings are dynamic. The concept of a fixed-size buffer
    # is handled by reading a specific number of bytes. The "allocation"
    # happens when the string object is created.
    
    # Read for the first buffer
    print("Enter up to 100 characters for the first buffer (press Ctrl+D/Ctrl+Z on a new line if done):")
    # The first method allocates a large buffer and copies in 100 characters.
    # We read at most 100 characters from stdin.
    try:
        buf = sys.stdin.read(100)
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # Read for the second buffer
    print("Enter up to 100 characters for the second buffer (press Ctrl+D/Ctrl+Z on a new line if done):")
    # The second method allocates another large buffer and copies in 100 characters.
    try:
        buf1 = sys.stdin.read(100)
    except Exception as e:
        print(f"An error occurred: {e}")
        return
        
    print(f"Content of first buffer: {buf}")
    print(f"Content of second buffer: {buf1}")
    # Memory is managed automatically by Python's garbage collector.

def main():
    """
    Main function to run 5 test cases.
    """
    # The prompt for stdin can be tricky in a loop.
    # We will inform the user how to run the tests.
    print("Running 5 Test Cases. Please provide input when prompted.")
    print("Note: stdin reads a fixed number of chars, including newlines.")
    print("You might need to press Enter and then provide more input for the second prompt.")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        perform_allocation_and_read()
    print("\nAll test cases finished.")

if __name__ == "__main__":
    main()