
import sys

def print_argument_at_index(args, index_str):
    index = int(index_str)
    if 0 <= index < len(args):
        print(args[index])
    else:
        print("Index out of bounds")

if __name__ == "__main__":
    # Test case 1
    test1 = ["program", "2", "hello", "world", "python"]
    print("Test 1:", end=" ")
    print_argument_at_index(test1, test1[1])
    
    # Test case 2
    test2 = ["program", "0", "first", "second", "third"]
    print("Test 2:", end=" ")
    print_argument_at_index(test2, test2[1])
    
    # Test case 3
    test3 = ["program", "3", "alpha", "beta", "gamma", "delta"]
    print("Test 3:", end=" ")
    print_argument_at_index(test3, test3[1])
    
    # Test case 4
    test4 = ["program", "1", "testing"]
    print("Test 4:", end=" ")
    print_argument_at_index(test4, test4[1])
    
    # Test case 5
    test5 = ["program", "5", "one", "two", "three"]
    print("Test 5:", end=" ")
    print_argument_at_index(test5, test5[1])
