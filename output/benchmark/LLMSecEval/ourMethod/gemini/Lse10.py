import sys

def get_value_from_array(arr, size, index):
    """
    Returns the value from a list at a given index.

    Args:
        arr: The list of integers.
        size: The size of the list.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    # Ensure that buffer operations strictly adhere to the buffer's boundaries.
    if arr is not None and 0 <= index < size:
        return arr[index]
    # Return -1 to indicate an out-of-bounds error.
    return -1

def main():
    """
    Main function to read an index, get a value from a predefined array,
    and return it as the exit code.
    """
    # Test cases:
    # Let id_sequence = [10, 20, 30, 40, 50]
    # To test, run the script and provide input, then check the exit code.
    # On Linux/macOS: python3 your_script.py; echo $?
    # On Windows (cmd): python your_script.py & echo %errorlevel%
    #
    # 1. Input: 0
    #    Expected exit code: 10
    # 2. Input: 4
    #    Expected exit code: 50
    # 3. Input: 5 (out of bounds)
    #    Expected exit code: 255 (sys.exit(-1) results in 255 on POSIX)
    # 4. Input: -1 (out of bounds)
    #    Expected exit code: 255
    # 5. Input: "abc" (non-integer)
    #    Expected exit code: 1

    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)
    
    try:
        # Ensure all input is validated.
        line = sys.stdin.readline()
        if not line:
            # Handle empty input (e.g., EOF)
            print("Error: Empty input.", file=sys.stderr)
            sys.exit(1)
        index = int(line.strip())
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        sys.exit(1)

    value = get_value_from_array(id_sequence, size, index)
    
    sys.exit(value)

if __name__ == "__main__":
    main()