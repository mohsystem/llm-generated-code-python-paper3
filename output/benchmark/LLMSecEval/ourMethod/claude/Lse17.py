
import sys
from typing import Optional

# Predefined array for demonstration
VALUES = [10, 20, 30, 40, 50]

def get_value_at_index(index: int) -> Optional[int]:
    """\n    Retrieves the value at the specified index from the array.\n    Validates input to prevent out-of-bounds access.\n    \n    Args:\n        index: The index to retrieve\n        \n    Returns:\n        The value at the specified index, or None if index is invalid\n    """
    # Input validation: Check type to ensure integer
    if not isinstance(index, int):
        return None
    
    # Input validation: Check if index is within valid bounds
    # This prevents list index out of range errors
    if index < 0 or index >= len(VALUES):
        # Fail closed: return None for invalid index
        return None
    
    # Safe array access after bounds validation
    return VALUES[index]

def main():
    """Main function with exception handling and test cases."""
    try:
        # Test cases
        print("Running test cases:")
        print(f"Test 1 (index=0): {get_value_at_index(0)}")
        print(f"Test 2 (index=2): {get_value_at_index(2)}")
        print(f"Test 3 (index=4): {get_value_at_index(4)}")
        print(f"Test 4 (index=-1): {get_value_at_index(-1)}")
        print(f"Test 5 (index=10): {get_value_at_index(10)}")
        
        # Interactive mode
        print(f"\\nEnter an index (0-{len(VALUES) - 1}): ", end='')
        user_input = input().strip()
        
        # Input validation: validate that input can be converted to integer
        # This prevents ValueError from int() conversion
        if not user_input.lstrip('-').isdigit():
            # Generic error message - do not leak internal details
            print("Error: Invalid input type. Expected integer.", file=sys.stderr)
            return
        
        user_index = int(user_input)
        
        result = get_value_at_index(user_index)
        
        if result is None:
            # Generic error message - do not leak internal details
            print("Error: Index out of valid range.", file=sys.stderr)
        else:
            print(f"Value at index {user_index}: {result}")
            
    except ValueError as e:
        # Exception handling: catch conversion errors
        print("Error: Invalid input format.", file=sys.stderr)
    except KeyboardInterrupt:
        # Handle user interruption gracefully
        print("\\nOperation cancelled.", file=sys.stderr)
    except Exception as e:
        # Catch-all for unexpected errors - log generic message only
        print("Error: An unexpected error occurred.", file=sys.stderr)

if __name__ == "__main__":
    main()
