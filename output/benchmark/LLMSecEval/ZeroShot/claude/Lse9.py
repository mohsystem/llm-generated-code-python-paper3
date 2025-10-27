
import sys

def get_argument_at_index(args, index):
    if args is None or index < 0 or index >= len(args):
        return "Error: Invalid index or no argument at the specified index"
    return args[index]

def main():
    # Test cases
    test_args1 = ["arg0", "arg1", "arg2", "arg3", "arg4"]
    
    # Test case 1: Get argument at index 1
    print("Test 1 - Index 1:", get_argument_at_index(test_args1, 1))
    
    # Test case 2: Get argument at index 3
    print("Test 2 - Index 3:", get_argument_at_index(test_args1, 3))
    
    # Test case 3: Get argument at index 0
    print("Test 3 - Index 0:", get_argument_at_index(test_args1, 0))
    
    # Test case 4: Invalid index (out of bounds)
    print("Test 4 - Index 10:", get_argument_at_index(test_args1, 10))
    
    # Test case 5: Negative index
    print("Test 5 - Index -1:", get_argument_at_index(test_args1, -1))
    
    # If actual command line arguments are provided
    if len(sys.argv) > 1:
        try:
            index = int(sys.argv[1])
            # Skip the script name and the index argument
            remaining_args = sys.argv[2:]
            print(f"\\nActual argument at index {index}:", 
                  get_argument_at_index(remaining_args, index))
        except ValueError:
            print("Error: First argument must be a valid integer")

if __name__ == "__main__":
    main()
