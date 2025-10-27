import sys

def get_value_at_index(argv):
    """
    Retrieves the value from the arguments list at the index specified by argv[1].

    :param argv: The list of command-line arguments.
    :return: The string at the specified index or an error message.
    """
    if len(argv) < 2:
        return "Error: Not enough arguments. Please provide an index."

    try:
        index_str = argv[1]
        index = int(index_str)
    except ValueError:
        return "Error: The index provided in the second argument must be an integer."

    if index < 0 or index >= len(argv):
        return f"Error: Index {index} is out of bounds for the given arguments."

    return argv[index]

if __name__ == "__main__":
    # Example with actual command line arguments
    print("--- Processing Actual Command Line Arguments ---")
    print(f"Arguments received: {sys.argv}")
    result = get_value_at_index(sys.argv)
    print(f"Result: {result}")
    print("\n--- Running 5 Hardcoded Test Cases ---")

    # Test Case 1: Valid case
    test1 = ["program", "3", "apple", "banana", "cherry"]
    print(f"Test 1: {test1}")
    print(f"Output: {get_value_at_index(test1)}") # Expected: cherry

    # Test Case 2: Index out of bounds
    test2 = ["program", "5", "one", "two"]
    print(f"\nTest 2: {test2}")
    print(f"Output: {get_value_at_index(test2)}") # Expected: Error

    # Test Case 3: Index is not a number
    test3 = ["program", "foo", "bar"]
    print(f"\nTest 3: {test3}")
    print(f"Output: {get_value_at_index(test3)}") # Expected: Error

    # Test Case 4: Not enough arguments
    test4 = ["program"]
    print(f"\nTest 4: {test4}")
    print(f"Output: {get_value_at_index(test4)}") # Expected: Error
    
    # Test Case 5: Index points to itself
    test5 = ["program", "1", "arg2", "arg3"]
    print(f"\nTest 5: {test5}")
    print(f"Output: {get_value_at_index(test5)}") # Expected: 1