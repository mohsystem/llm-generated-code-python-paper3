
import sys
from typing import Optional

# Predefined array of id_sequence values
ID_SEQUENCE = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]

def get_value_at_index(index: int) -> int:
    """\n    Retrieves value at specified index from id_sequence array\n    \n    Args:\n        index: The index to retrieve (must be within array bounds)\n    \n    Returns:\n        The value at the specified index\n    \n    Raises:\n        ValueError: if index is out of bounds\n    """
    # Input validation: check if index is within valid bounds
    if not isinstance(index, int):
        raise ValueError("Index must be an integer")
    
    if index < 0 or index >= len(ID_SEQUENCE):
        raise ValueError(f"Invalid index: must be between 0 and {len(ID_SEQUENCE) - 1}")
    
    # Return value at valid index
    return ID_SEQUENCE[index]

def prompt_and_get_value() -> Optional[int]:
    """\n    Prompts user for index and returns corresponding value\n    \n    Returns:\n        The value at user-specified index, or None on error\n    """
    try:
        # Prompt user for input
        user_input = input(f"Enter an index value (0-{len(ID_SEQUENCE) - 1}): ")
        
        # Validate and convert input to integer
        try:
            index = int(user_input)
        except ValueError:
            print("Error: Invalid input type", file=sys.stderr)
            return None
        
        return get_value_at_index(index)
        
    except ValueError as e:
        # Handle out of bounds error without exposing internals
        print(f"Error: {e}", file=sys.stderr)
        return None
    except Exception as e:
        # Catch any other exceptions
        print("Error: Invalid input", file=sys.stderr)
        return None

def main():
    """Main function with test cases"""
    
    # Test case 1: Valid index at start
    print("\\nTest case 1: Valid index 0")
    try:
        result = get_value_at_index(0)
        print(f"Value at index 0: {result}")
    except Exception as e:
        print(f"Test 1 failed: {e}", file=sys.stderr)
    
    # Test case 2: Valid index in middle
    print("\\nTest case 2: Valid index 5")
    try:
        result = get_value_at_index(5)
        print(f"Value at index 5: {result}")
    except Exception as e:
        print(f"Test 2 failed: {e}", file=sys.stderr)
    
    # Test case 3: Valid index at end
    print("\\nTest case 3: Valid index 9")
    try:
        result = get_value_at_index(9)
        print(f"Value at index 9: {result}")
    except Exception as e:
        print(f"Test 3 failed: {e}", file=sys.stderr)
    
    # Test case 4: Invalid negative index
    print("\\nTest case 4: Invalid index -1")
    try:
        result = get_value_at_index(-1)
        print(f"Value at index -1: {result}")
    except Exception as e:
        print(f"Test 4 failed (expected): {e}", file=sys.stderr)
    
    # Test case 5: Invalid out of bounds index
    print("\\nTest case 5: Invalid index 15")
    try:
        result = get_value_at_index(15)
        print(f"Value at index 15: {result}")
    except Exception as e:
        print(f"Test 5 failed (expected): {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
