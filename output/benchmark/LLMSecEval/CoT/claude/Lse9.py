
import sys

def get_argument_at_index(args, index):
    """\n    Safely retrieve argument at specified index\n    """
    # Validate input parameters
    if args is None:
        return "Error: Arguments list is None"
    
    # Validate index is non-negative
    if index < 0:
        return "Error: Index cannot be negative"
    
    # Check if index is within bounds
    if index >= len(args):
        return "Error: Index out of bounds"
    
    return args[index]

def main():
    # Test cases
    print("Test Case 1:")
    test1 = ["arg0", "arg1", "arg2", "arg3", "arg4"]
    print(get_argument_at_index(test1, 1))
    
    print("\\nTest Case 2:")
    test2 = ["arg0", "arg1", "arg2", "arg3", "arg4"]
    print(get_argument_at_index(test2, 3))
    
    print("\\nTest Case 3:")
    test3 = ["arg0", "arg1"]
    print(get_argument_at_index(test3, 0))
    
    print("\\nTest Case 4:")
    test4 = ["arg0", "arg1", "arg2"]
    print(get_argument_at_index(test4, 5))
    
    print("\\nTest Case 5:")
    test5 = ["arg0", "arg1", "arg2"]
    print(get_argument_at_index(test5, -1))
    
    # Real command line usage
    if len(sys.argv) > 1:
        try:
            index = int(sys.argv[1])
            result = get_argument_at_index(sys.argv, index)
            print(f"\\nCommand line result: {result}")
        except ValueError:
            print("Error: First argument must be a valid integer")

if __name__ == "__main__":
    main()
