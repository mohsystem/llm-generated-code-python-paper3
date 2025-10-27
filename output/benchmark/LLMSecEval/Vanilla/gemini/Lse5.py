import sys

def get_element_at_index(data, index):
    """
    Accepts a list and an index, then prints the element at that index.
    It includes error handling for out-of-bounds indices.
    
    :param data: The list to access.
    :param index: The index of the element to print.
    """
    try:
        print(f"Element at index {index}: {data[index]}")
    except IndexError:
        print(f"Error: Index {index} is out of bounds for a list of size {len(data)}.")

def main():
    elements = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # Check if a command-line argument is provided
    if len(sys.argv) > 1:
        try:
            index_from_arg = int(sys.argv[1])
            print("--- Running with command-line argument ---")
            get_element_at_index(elements, index_from_arg)
        except ValueError:
            print("Error: Command-line argument must be a valid integer.")
    else:
        # If no command-line arguments, run the 5 built-in test cases
        print("--- Running built-in test cases ---")
        
        # Test Case 1: Accessing the first element
        get_element_at_index(elements, 0)
        
        # Test Case 2: Accessing an element in the middle
        get_element_at_index(elements, 4)
        
        # Test Case 3: Accessing the last element
        get_element_at_index(elements, 9)
        
        # Test Case 4: Accessing with a negative index (out of bounds for this example's logic)
        get_element_at_index(elements, -11) # Python's negative indexing is different, so use an invalid one
        
        # Test Case 5: Accessing an index equal to the list length (out of bounds)
        get_element_at_index(elements, 10)

if __name__ == "__main__":
    main()