
import sys
from typing import Optional

# Predefined array with fixed bounds
id_sequence = [100, 200, 300, 400, 500]

def get_value_at_index(index: int) -> Optional[int]:
    """\n    Retrieves value at specified index from id_sequence array.\n    Validates index to prevent out-of-bounds access.\n    \n    Args:\n        index: The index to retrieve from id_sequence\n        \n    Returns:\n        The value at the specified index, or None if invalid\n    """
    # Input validation: Check type
    if not isinstance(index, int):
        print("Error: Invalid index type", file=sys.stderr)
        return None
    
    # Input validation: Check bounds to prevent array access violations
    # Reject negative indices and indices beyond array length
    if index < 0 or index >= len(id_sequence):
        # Fail closed: return None without exposing internal details
        print("Error: Invalid index", file=sys.stderr)
        return None
    
    # Bounds checked: safe to access array
    return id_sequence[index]

def prompt_and_get_value() -> Optional[int]:
    """\n    Prompts user for index and returns corresponding value.\n    Validates all user input before processing.\n    \n    Returns:\n        The value at user-specified index, or None on error\n    """
    try:
        # Prompt user with clear range information
        user_input = input(f"Enter index (0-{len(id_sequence) - 1}): ")
        
        # Input validation: Check if input can be converted to integer
        try:
            index = int(user_input)
        except ValueError:
            # Type validation failed
            print("Error: Invalid input type", file=sys.stderr)
            return None
        
        # Delegate to validated function
        return get_value_at_index(index)
        
    except EOFError:
        # Handle end of input gracefully
        print("Error: Input terminated", file=sys.stderr)
        return None
    except Exception:
        # Catch-all for unexpected errors, no internal details leaked
        print("Error: Processing failed", file=sys.stderr)
        return None

def main():
    """Test cases demonstrating secure usage"""
    # Test case 1: Valid index at start
    print(f"Test 1 - Index 0: {get_value_at_index(0)}")
    
    # Test case 2: Valid index in middle
    print(f"Test 2 - Index 2: {get_value_at_index(2)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 - Index 4: {get_value_at_index(4)}")
    
    # Test case 4: Invalid negative index
    print(f"Test 4 - Index -1: {get_value_at_index(-1)}")
    
    # Test case 5: Invalid index beyond bounds
    print(f"Test 5 - Index 10: {get_value_at_index(10)}")

if __name__ == "__main__":
    main()
