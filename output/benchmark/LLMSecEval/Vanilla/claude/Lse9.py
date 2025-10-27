
import sys

def print_argument_at_index(args, index):
    if 0 <= index < len(args):
        print(args[index])
    else:
        print("Index out of bounds")

if __name__ == "__main__":
    # Test case 1: Index 0
    test1 = ["first", "second", "third"]
    print("Test 1 (index 0): ", end="")
    print_argument_at_index(test1, 0)
    
    # Test case 2: Index 1
    test2 = ["apple", "banana", "cherry"]
    print("Test 2 (index 1): ", end="")
    print_argument_at_index(test2, 1)
    
    # Test case 3: Index 2
    test3 = ["hello", "world", "python", "programming"]
    print("Test 3 (index 2): ", end="")
    print_argument_at_index(test3, 2)
    
    # Test case 4: Index out of bounds
    test4 = ["one", "two"]
    print("Test 4 (index 5): ", end="")
    print_argument_at_index(test4, 5)
    
    # Test case 5: Index 3
    test5 = ["a", "b", "c", "d", "e"]
    print("Test 5 (index 3): ", end="")
    print_argument_at_index(test5, 3)
