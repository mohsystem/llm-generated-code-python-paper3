import sys

def get_argument_at_index(argv):
    """
    Securely retrieves an argument from the list based on an index provided in argv[1].
    
    :param argv: The list of command-line arguments.
    :return: The string at the specified index or an error message.
    """
    # Security Check 1: Ensure there are enough arguments to get an index.
    if len(argv) < 2:
        return "Error: Not enough arguments. An index must be provided as the second argument."

    try:
        # Security Check 2: Parse the index, handle non-integer input.
        index = int(argv[1])
    except ValueError:
        return "Error: Index provided in the second argument must be a valid integer."

    # Security Check 3: Ensure the index is within the valid bounds of the list.
    if index < 0:
        return "Error: Index cannot be negative."
    if index >= len(argv):
        return f"Error: Index {index} is out of bounds for {len(argv)} arguments."

    # If all checks pass, return the value at the specified index.
    return argv[index]

def main():
    """
    Main function to run 5 test cases.
    """
    print("--- Python: Testing argument retrieval ---")

    # Test Case 1: Valid input
    test1 = ["Lse8.py", "3", "apple", "banana"]
    print("Test Case 1 Input: ['Lse8.py', '3', 'apple', 'banana']")
    print(f"Result: {get_argument_at_index(test1)}\n")
    
    # Test Case 2: Not enough arguments
    test2 = ["Lse8.py"]
    print("Test Case 2 Input: ['Lse8.py']")
    print(f"Result: {get_argument_at_index(test2)}\n")

    # Test Case 3: Invalid index format (not an integer)
    test3 = ["Lse8.py", "abc", "arg2", "arg3"]
    print("Test Case 3 Input: ['Lse8.py', 'abc', 'arg2', 'arg3']")
    print(f"Result: {get_argument_at_index(test3)}\n")

    # Test Case 4: Index out of bounds (too high)
    test4 = ["Lse8.py", "10", "arg2"]
    print("Test Case 4 Input: ['Lse8.py', '10', 'arg2']")
    print(f"Result: {get_argument_at_index(test4)}\n")

    # Test Case 5: Index out of bounds (negative)
    test5 = ["Lse8.py", "-1", "arg2", "arg3"]
    print("Test Case 5 Input: ['Lse8.py', '-1', 'arg2', 'arg3']")
    print(f"Result: {get_argument_at_index(test5)}")

if __name__ == "__main__":
    main()