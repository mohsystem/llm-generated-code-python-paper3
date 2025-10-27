
import sys

def get_argument_at_index(args):
    """\n    Securely retrieves the argument at the index specified by args[1]\n    """
    # Security check: Validate arguments list
    if args is None or len(args) < 2:
        return "Error: Insufficient arguments. Need at least 2 arguments."
    
    try:
        # Security check: Safely parse the index
        index = int(args[1])
        
        # Security check: Validate index bounds
        if index < 0 or index >= len(args):
            return f"Error: Index out of bounds. Valid range: 0 to {len(args) - 1}"
        
        # Return the value at the specified index
        return args[index]
        
    except ValueError:
        return "Error: Invalid index format. Index must be an integer."
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"

def main():
    # Test case 1: Normal case
    test1 = ["program", "2", "hello", "world"]
    print(f"Test 1: {get_argument_at_index(test1)}")
    
    # Test case 2: Index out of bounds
    test2 = ["program", "10", "hello"]
    print(f"Test 2: {get_argument_at_index(test2)}")
    
    # Test case 3: Invalid index format
    test3 = ["program", "abc", "hello"]
    print(f"Test 3: {get_argument_at_index(test3)}")
    
    # Test case 4: Insufficient arguments
    test4 = ["program"]
    print(f"Test 4: {get_argument_at_index(test4)}")
    
    # Test case 5: Negative index
    test5 = ["program", "-1", "hello"]
    print(f"Test 5: {get_argument_at_index(test5)}")

if __name__ == "__main__":
    main()
