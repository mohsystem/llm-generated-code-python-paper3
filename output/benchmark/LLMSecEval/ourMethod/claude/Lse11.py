
import sys

def get_value_from_array(array, size, index):
    """\n    Get value from array with bounds checking.\n    Returns the value at the given index if valid, otherwise returns -1.\n    """
    # Security: Validate array is not None
    if array is None:
        print("Error: Array is None", file=sys.stderr)
        return -1
    
    # Security: Validate size parameter matches actual array length
    if size != len(array):
        print("Error: Size mismatch", file=sys.stderr)
        return -1
    
    # Security: Bounds checking to prevent out-of-bounds access
    if index < 0 or index >= size:
        print("Error: Index out of bounds", file=sys.stderr)
        return -1
    
    # Safe to access array element after validation
    return array[index]


def main():
    # Predefined array for testing
    id_sequence = [10, 20, 30, 40, 50]
    
    try:
        # Security: Validate and sanitize input
        user_input = input("Enter index: ").strip()
        
        # Security: Validate input is a valid integer
        if not user_input.lstrip('-').isdigit():
            print("Error: Invalid input", file=sys.stderr)
            sys.exit(1)
        
        index = int(user_input)
        
        # Security: Additional bounds check before conversion
        # Prevent extremely large values that could cause issues
        if index < -2147483648 or index > 2147483647:
            print("Error: Index out of range", file=sys.stderr)
            sys.exit(1)
        
        # Call function and get result
        result = get_value_from_array(id_sequence, len(id_sequence), index)
        
        # Exit with the result as exit code
        # Note: Exit codes are typically 0-255, values outside may be truncated
        sys.exit(result if result >= 0 else 1)
        
    except ValueError:
        # Security: Handle conversion errors
        print("Error: Invalid integer", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Security: Catch any unexpected exceptions
        print("Error occurred", file=sys.stderr)
        sys.exit(1)


# Test cases
def run_tests():
    id_sequence = [10, 20, 30, 40, 50]
    print("Test 1 - Valid index 0:", get_value_from_array(id_sequence, len(id_sequence), 0))  # Expected: 10
    print("Test 2 - Valid index 4:", get_value_from_array(id_sequence, len(id_sequence), 4))  # Expected: 50
    print("Test 3 - Invalid index -1:", get_value_from_array(id_sequence, len(id_sequence), -1))  # Expected: -1
    print("Test 4 - Invalid index 5:", get_value_from_array(id_sequence, len(id_sequence), 5))  # Expected: -1
    print("Test 5 - Null array:", get_value_from_array(None, 0, 0))  # Expected: -1


if __name__ == "__main__":
    main()
    # Uncomment to run tests instead:
    # run_tests()
