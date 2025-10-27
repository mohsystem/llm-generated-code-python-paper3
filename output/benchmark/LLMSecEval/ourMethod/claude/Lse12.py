
import sys

def get_value_from_array(array, size, index):
    """\n    Returns the value at the given index from the array.\n    Security: Validates all inputs to prevent buffer overflows and out-of-bounds access.\n    """
    # Validate array is not None
    if array is None:
        print("Error: Null array provided", file=sys.stderr)
        return -1
    
    # Validate size parameter matches actual array length
    if size != len(array):
        print("Error: Size mismatch", file=sys.stderr)
        return -1
    
    # Bounds checking: ensure index is within valid range [0, size)
    # This prevents both negative indices and out-of-bounds access
    if not isinstance(index, int) or index < 0 or index >= size:
        print("Error: Index out of bounds", file=sys.stderr)
        return -1
    
    return array[index]


def main():
    """Main function with 5 test cases."""
    # Predefined test array - fixed size for security
    test_array = [10, 20, 30, 40, 50]
    size = len(test_array)
    
    try:
        # Read index from standard input - treat as untrusted
        user_input = input().strip()
        
        # Validate input is a valid integer
        if not user_input.lstrip('-').isdigit():
            print("Error: Invalid input", file=sys.stderr)
            sys.exit(1)
        
        index = int(user_input)
        
        # Call function with validated parameters
        result = get_value_from_array(test_array, size, index)
        
        # Exit with result as exit code (constrained to valid range 0-255)
        sys.exit(abs(result) % 256)
        
    except ValueError:
        # Handle conversion errors
        print("Error: Invalid input format", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Catch all other exceptions - generic error message only
        print("Error: Processing failed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Test cases (commented out during normal execution)
    # Uncomment to run tests instead of reading from stdin
    """\n    test_cases = [\n        (2, 30),   # Valid index\n        (0, 10),   # First element\n        (4, 50),   # Last element\n        (-1, -1),  # Invalid negative index\n        (10, -1)   # Invalid out-of-bounds index\n    ]\n    \n    test_array = [10, 20, 30, 40, 50]\n    for idx, expected in test_cases:\n        result = get_value_from_array(test_array, len(test_array), idx)\n        print(f"Index {idx}: {result} (expected {expected})")\n    """
    
    main()
