
import sys

def get_element_at_index(args):
    """\n    Retrieves an element from a predefined array at the specified index.\n    \n    Args:\n        args: List of command line arguments\n        \n    Returns:\n        String containing the element or error message\n    """
    # Predefined array of elements
    elements = ["apple", "banana", "cherry", "date", "elderberry"]
    
    # Validate that we have at least one argument
    if not args or len(args) == 0:
        return "Error: No index provided"
    
    # Validate and parse the index
    try:
        # Parse the first argument as integer
        index = int(args[0])
    except (ValueError, TypeError):
        return "Error: Invalid index format"
    
    # Bounds checking - ensure index is within valid range
    if index < 0 or index >= len(elements):
        return "Error: Index out of bounds"
    
    # Return the element at the validated index
    return elements[index]

if __name__ == "__main__":
    # Test case 1: Valid index 0
    test1 = ["0"]
    print(f"Test 1 (index 0): {get_element_at_index(test1)}")
    
    # Test case 2: Valid index 2
    test2 = ["2"]
    print(f"Test 2 (index 2): {get_element_at_index(test2)}")
    
    # Test case 3: Valid index 4 (last element)
    test3 = ["4"]
    print(f"Test 3 (index 4): {get_element_at_index(test3)}")
    
    # Test case 4: Invalid index (out of bounds)
    test4 = ["10"]
    print(f"Test 4 (index 10): {get_element_at_index(test4)}")
    
    # Test case 5: Invalid input (not a number)
    test5 = ["abc"]
    print(f"Test 5 (invalid): {get_element_at_index(test5)}")
