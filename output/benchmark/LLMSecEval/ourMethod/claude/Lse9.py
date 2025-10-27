
import sys
from typing import List, Optional

def get_argument_at_index(args: List[str], index: int) -> str:
    """\n    Retrieves and returns the command line argument at the specified index.\n    \n    Args:\n        args: The command line arguments list\n        index: The index to retrieve (0-based after program name)\n    \n    Returns:\n        The argument at the specified index, or an error message if invalid\n    """
    # Validate that args is not None to prevent AttributeError
    if args is None:
        return "Error: Arguments list is None"
    
    # Validate index is non-negative to prevent list access violations
    if index < 0:
        return "Error: Index cannot be negative"
    
    # Check if index is within bounds to prevent IndexError
    # This prevents buffer over-read vulnerabilities
    if index >= len(args):
        return "Error: Index out of bounds"
    
    # Return the argument at the valid index
    return args[index]

def main():
    """Main function with test cases and command line argument processing."""
    
    # Test case 1: Valid index within bounds
    test1 = ["arg0", "arg1", "arg2", "arg3"]
    print(f"Test 1 - Index 1: {get_argument_at_index(test1, 1)}")
    
    # Test case 2: Valid index at boundary
    test2 = ["first", "second", "third"]
    print(f"Test 2 - Index 2: {get_argument_at_index(test2, 2)}")
    
    # Test case 3: Index out of bounds (should return error)
    test3 = ["only", "two"]
    print(f"Test 3 - Index 5: {get_argument_at_index(test3, 5)}")
    
    # Test case 4: Negative index (should return error)
    test4 = ["some", "args"]
    print(f"Test 4 - Index -1: {get_argument_at_index(test4, -1)}")
    
    # Test case 5: Empty list with index 0 (should return error)
    test5 = []
    print(f"Test 5 - Index 0 on empty: {get_argument_at_index(test5, 0)}")
    
    # Actual program logic: process command line arguments if provided
    # sys.argv[0] is the program name, so we start from index 1
    if len(sys.argv) > 1:
        try:
            # Parse the first argument as the index with validation
            index = int(sys.argv[1])
            
            # The actual arguments start from index 2 (after program name and index)
            actual_args = sys.argv[2:]
            
            # Retrieve and print the argument at the specified index
            result = get_argument_at_index(actual_args, index)
            print(result)
            
        except ValueError:
            # Handle invalid number format without exposing internal details
            print("Error: Invalid index format")

if __name__ == "__main__":
    main()
