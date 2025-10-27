
import sys

def process_arguments(args):
    # Validate we have at least 2 arguments
    if args is None or len(args) < 2:
        print("Error: Insufficient arguments")
        return
    
    try:
        # Convert string at index 1 to integer
        index = int(args[1])
        
        # Validate index is within bounds
        if index < 0 or index >= len(args):
            print("Error: Index out of bounds")
            return
        
        # Print the argument at the specified index
        print(args[index])
        
    except ValueError:
        print("Error: Invalid index format")
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # Test case 1: Valid index
    test1 = ["arg0", "2", "Hello", "World"]
    print("Test 1: ", end="")
    process_arguments(test1)
    
    # Test case 2: Index out of bounds
    test2 = ["arg0", "10", "Hello"]
    print("Test 2: ", end="")
    process_arguments(test2)
    
    # Test case 3: Invalid index format
    test3 = ["arg0", "abc", "Hello"]
    print("Test 3: ", end="")
    process_arguments(test3)
    
    # Test case 4: Insufficient arguments
    test4 = ["arg0"]
    print("Test 4: ", end="")
    process_arguments(test4)
    
    # Test case 5: Access first argument
    test5 = ["First", "0", "Second", "Third"]
    print("Test 5: ", end="")
    process_arguments(test5)

if __name__ == "__main__":
    main()
