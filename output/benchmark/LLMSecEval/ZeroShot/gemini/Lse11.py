import sys

id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
id_sequence_size = len(id_sequence)

def getValueFromArray(array, size, index):
    """
    Securely gets a value from a list at a given index.
    Performs bounds checking to prevent out-of-bounds access.
    If the index is out of bounds, it prints an error and terminates the program.

    Args:
        array: The list to access.
        size: The size of the list.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.
    """
    # Securely check if the index is within the valid bounds of the list.
    if index < 0 or index >= size:
        print("Error: Index out of bounds.", file=sys.stderr)
        # Exit with a non-zero status code to indicate an error.
        sys.exit(1)
    return array[index]

def main():
    """
    Main function to read an index, get the value, and exit with that value.
    """
    # Test cases to run manually by providing input:
    # 1. Input: 3  (valid index) 
    #    Expected: Program exits with code 40.
    # 2. Input: 0  (valid first element)
    #    Expected: Program exits with code 10.
    # 3. Input: 9  (valid last element)
    #    Expected: Program exits with code 100.
    # 4. Input: -1 (invalid, negative)
    #    Expected: "Error: Index out of bounds." on stderr, program exits with code 1.
    # 5. Input: 10 (invalid, too large)
    #    Expected: "Error: Index out of bounds." on stderr, program exits with code 1.

    try:
        # Read a line and convert to integer
        line = sys.stdin.readline()
        if not line:
            print("Error: No input received.", file=sys.stderr)
            sys.exit(1)
        index = int(line.strip())
    except (ValueError, TypeError):
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        sys.exit(1)
        
    value = getValueFromArray(id_sequence, id_sequence_size, index)
    
    # The returned value is used as the exit code.
    # Note: Exit codes on Unix-like systems are typically 0-255.
    sys.exit(value)

if __name__ == "__main__":
    main()