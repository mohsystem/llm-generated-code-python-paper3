
import sys

def process_command_line_arguments(args, index):
    if args is None or len(args) == 0:
        print("No arguments provided")
        return
    
    if index < 0 or index >= len(args):
        print("Index out of bounds")
        return
    
    print(args[index])

if __name__ == "__main__":
    # Test case 1: Normal case
    test1 = ["arg0", "2", "arg2", "arg3"]
    print("Test 1:")
    index1 = int(test1[1])
    process_command_line_arguments(test1, index1)
    
    # Test case 2: Index at boundary
    test2 = ["arg0", "0", "arg2"]
    print("\\nTest 2:")
    index2 = int(test2[1])
    process_command_line_arguments(test2, index2)
    
    # Test case 3: Last element
    test3 = ["arg0", "3", "arg2", "arg3"]
    print("\\nTest 3:")
    index3 = int(test3[1])
    process_command_line_arguments(test3, index3)
    
    # Test case 4: Out of bounds
    test4 = ["arg0", "5", "arg2"]
    print("\\nTest 4:")
    index4 = int(test4[1])
    process_command_line_arguments(test4, index4)
    
    # Test case 5: Empty array handling
    test5 = []
    print("\\nTest 5:")
    process_command_line_arguments(test5, 0)
