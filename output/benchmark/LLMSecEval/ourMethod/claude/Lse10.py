
import sys

def get_value_from_array(array, size, index):
    """\n    Get value from array with bounds checking.\n    Returns the value at the given index if valid, otherwise returns -1.\n    """
    # Validate input parameters to prevent out-of-bounds access
    if array is None:
        print("Error: Array is None", file=sys.stderr)
        return -1
    
    # Ensure index is within valid bounds [0, size-1]
    if index < 0 or index >= size:
        print("Error: Index out of bounds", file=sys.stderr)
        return -1
    
    # Ensure size matches actual array length to prevent inconsistencies
    if size > len(array):
        print("Error: Size exceeds array length", file=sys.stderr)
        return -1
    
    # Safe to access array at this point
    return array[index]

def main():
    # Predefined array for testing
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)
    
    try:
        # Read index from standard input with validation
        input_line = sys.stdin.readline().strip()
        
        # Validate input is not empty
        if not input_line:
            print("Error: Empty input", file=sys.stderr)
            sys.exit(1)
        
        # Parse input as integer with error handling
        try:
            index = int(input_line)
        except ValueError:
            print("Error: Invalid integer input", file=sys.stderr)
            sys.exit(1)
        
        # Get value from array with bounds checking
        result = get_value_from_array(id_sequence, size, index)
        
        # Exit with the retrieved value (or error code -1)
        # Ensure exit code is in valid range [0, 255]
        exit_code = result if 0 <= result <= 255 else (result & 0xFF)
        sys.exit(exit_code)
        
    except Exception as e:
        # Handle any unexpected exceptions
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Test cases (uncomment to run)
    """\n    id_sequence = [10, 20, 30, 40, 50]\n    size = len(id_sequence)\n    print(f"Test 1 (index 0): {get_value_from_array(id_sequence, size, 0)}")  # Expected: 10\n    print(f"Test 2 (index 2): {get_value_from_array(id_sequence, size, 2)}")  # Expected: 30\n    print(f"Test 3 (index 4): {get_value_from_array(id_sequence, size, 4)}")  # Expected: 50\n    print(f"Test 4 (index -1): {get_value_from_array(id_sequence, size, -1)}")  # Expected: -1\n    print(f"Test 5 (index 10): {get_value_from_array(id_sequence, size, 10)}")  # Expected: -1\n    """
    main()
