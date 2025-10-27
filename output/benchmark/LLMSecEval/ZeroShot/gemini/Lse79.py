import sys

def perform_allocation_and_read():
    """
    Reads two lines from stdin and securely stores up to 100 characters of each,
    simulating buffer allocation and safe reading.
    """
    # In Python, memory is managed automatically. A string variable acts as our "buffer".

    # 1. Read and process first input.
    print("Enter text for the first buffer: ", end='', flush=True)
    # Read the whole line to ensure stdin is cleared for the next prompt.
    line1 = sys.stdin.readline()
    # Securely take only the first 100 characters. strip() removes trailing whitespace/newline.
    buf = line1[:100].strip()

    # 2. Read and process second input.
    print("Enter text for the second buffer: ", end='', flush=True)
    line2 = sys.stdin.readline()
    buf1 = line2[:100].strip()

    # Print results.
    print("\n--- Contents ---")
    print(f"First buffer: {buf}")
    print(f"Second buffer: {buf1}")
    print("----------------\n")

def main():
    """ Main function to run test cases. """
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        perform_allocation_and_read()

if __name__ == "__main__":
    main()