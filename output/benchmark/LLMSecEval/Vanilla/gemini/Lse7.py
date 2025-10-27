import sys

def print_arg_from_index(args):
    """
    Converts the string at index 1 of the args list to an integer 'INDEX',
    then prints the argument at position 'INDEX'.

    :param args: A list of strings, simulating command-line arguments (e.g., sys.argv)
                 where args[0] is the script name and args[1] is the index.
    """
    # Check if there are enough arguments to proceed. We need at least 2.
    if len(args) <= 1:
        print("Error: Not enough arguments. Please provide an index.")
        return

    try:
        # Convert the second argument (at index 1) to an integer.
        index = int(args[1])
    except ValueError:
        print("Error: The second argument must be a valid integer.")
        return

    # Check if the parsed index is within the valid bounds of the list.
    if not (0 <= index < len(args)):
        print(f"Error: Index {index} is out of bounds for the given arguments.")
        return

    # Print the argument at the specified index.
    print(args[index])

if __name__ == "__main__":
    # --- 5 Test Cases ---

    # Test Case 1: Valid case, should print "banana"
    print("--- Test Case 1 ---")
    test1 = ["script.py", "3", "apple", "banana", "cherry"]
    print(f"Input: {test1}")
    print("Output: ", end="")
    print_arg_from_index(test1)
    print()

    # Test Case 2: Valid case, index 0, should print the script name
    print("--- Test Case 2 ---")
    test2 = ["script.py", "0"]
    print(f"Input: {test2}")
    print("Output: ", end="")
    print_arg_from_index(test2)
    print()

    # Test Case 3: Error case, index out of bounds
    print("--- Test Case 3 ---")
    test3 = ["script.py", "5", "a", "b"]
    print(f"Input: {test3}")
    print("Output: ", end="")
    print_arg_from_index(test3)
    print()

    # Test Case 4: Error case, non-integer index
    print("--- Test Case 4 ---")
    test4 = ["script.py", "two", "a", "b"]
    print(f"Input: {test4}")
    print("Output: ", end="")
    print_arg_from_index(test4)
    print()

    # Test Case 5: Error case, not enough arguments
    print("--- Test Case 5 ---")
    test5 = ["script.py"]
    print(f"Input: {test5}")
    print("Output: ", end="")
    print_arg_from_index(test5)
    print()