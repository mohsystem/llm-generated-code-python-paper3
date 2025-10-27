
import sys

# Predefined array of ID sequences
id_sequence = [100, 200, 300, 400, 500]

def get_id_at_index(index):
    """\n    Returns the value at the specified index in the id_sequence array.\n    Validates index bounds before access to prevent out-of-bounds errors.\n    \n    Args:\n        index: The index to retrieve (must be an integer)\n    \n    Returns:\n        The value at the specified index, or None if index is invalid\n    """
    # Type validation: ensure index is an integer
    if not isinstance(index, int):
        return None
    
    # Input validation: check if index is within valid bounds
    # This prevents list index out-of-bounds access (CWE-125)
    if index < 0 or index >= len(id_sequence):
        # Fail closed: return None without exposing internal details
        return None
    
    # Safe array access after bounds validation
    return id_sequence[index]

def test_case(index, expected):
    """Helper function to run test cases"""
    result = get_id_at_index(index)
    status = "PASS" if result == expected else "FAIL"
    print(f"Test: index={index}, expected={expected}, got={result} - {status}")

def main():
    """Main function to handle user input and testing"""
    try:
        # Run test cases
        print("Running test cases:")
        test_case(0, 100)
        test_case(2, 300)
        test_case(4, 500)
        test_case(-1, None)  # Invalid: negative index
        test_case(10, None)  # Invalid: index out of bounds
        
        print("\\nInteractive mode:")
        user_input = input(f"Enter an index value (0-{len(id_sequence) - 1}): ")
        
        # Input validation: sanitize and validate user input
        # Strip whitespace to prevent injection attempts
        user_input = user_input.strip()
        
        # Validate input is numeric before conversion
        if not user_input.lstrip('-').isdigit():
            # Generic error message - does not expose internal details
            print("Error: Invalid input. Please enter a valid integer.")
            return
        
        # Convert to integer with bounds checking
        try:
            index = int(user_input)
        except (ValueError, OverflowError):
            print("Error: Invalid input. Please enter a valid integer.")
            return
        
        result = get_id_at_index(index)
        
        # Check result and provide appropriate feedback
        if result is None:
            # Generic error message - does not expose internal details
            print("Error: Invalid index.")
        else:
            print(f"Value at index {index}: {result}")
            
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\\nOperation cancelled.")
        sys.exit(0)
    except Exception:
        # Catch-all for unexpected errors - do not expose details
        print("Error: An unexpected error occurred.")
        sys.exit(1)

if __name__ == "__main__":
    main()
