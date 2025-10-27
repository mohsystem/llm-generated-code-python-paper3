
import sys

def get_argument_at_index(args):
    """\n    Returns the command line argument at the index specified by args[1].\n    \n    Args:\n        args: List of command line arguments\n        \n    Returns:\n        The argument at the specified index, or None if invalid\n    """
    # Check if we have at least 2 arguments
    if args is None or len(args) < 2:
        return None
    
    try:
        # Parse the index from the second argument (argv[1])
        # This could raise ValueError if not a valid integer
        index = int(args[1])
        
        # Validate index is non-negative to prevent negative array access
        if index < 0:
            return None
        
        # Check bounds to prevent IndexError
        # Index must be less than list length
        if index >= len(args):
            return None
        
        # Return the value at the validated index
        return args[index]
        
    except (ValueError, TypeError):
        # args[1] is not a valid integer or args is not subscriptable
        return None


def main():
    """Test the function with various test cases."""
    # Test case 1: Valid index within bounds
    test1 = ["program", "2", "hello", "world"]
    print(f"Test 1: {get_argument_at_index(test1)}")  # Expected: "hello"
    
    # Test case 2: Index out of bounds
    test2 = ["program", "5", "hello"]
    print(f"Test 2: {get_argument_at_index(test2)}")  # Expected: None
    
    # Test case 3: Negative index
    test3 = ["program", "-1", "hello"]
    print(f"Test 3: {get_argument_at_index(test3)}")  # Expected: None
    
    # Test case 4: Invalid index format
    test4 = ["program", "abc", "hello"]
    print(f"Test 4: {get_argument_at_index(test4)}")  # Expected: None
    
    # Test case 5: Insufficient arguments
    test5 = ["program"]
    print(f"Test 5: {get_argument_at_index(test5)}")  # Expected: None


if __name__ == "__main__":
    main()
