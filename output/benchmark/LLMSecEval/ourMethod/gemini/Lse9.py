import sys

def get_argument_at_index(argv):
    """
    Retrieves a command-line argument by an index specified in the first argument.
    
    Args:
        argv: The list of command-line arguments from sys.argv.
    
    Returns:
        The argument at the specified index, or an error message string.
    """
    # argv[0] is the script name.
    # We expect at least two arguments: script name and the index string.
    if len(argv) < 2:
        return "Error: No index provided."

    index_str = argv[1]
    try:
        target_index = int(index_str)
    except ValueError:
        return f"Error: Index '{index_str}' is not a valid integer."

    # Per prompt, user-provided index is 1-based relative to user args,
    # mapping directly to argv indices. e.g., index 1 means argv[1].
    # We enforce positive indices as 0 is the script name.
    if target_index <= 0:
        return "Error: Index must be a positive integer."

    if target_index >= len(argv):
        return f"Error: Index {target_index} is out of bounds. There are only {len(argv)} command-line arguments."

    return argv[target_index]

def main():
    """Main function to run the script and test cases."""
    # To run with actual command-line arguments, execute:
    # python your_script.py 2 zero one two three  (should print "zero")
    # python your_script.py 1 one two             (should print "1")
    # python your_script.py 5 1 2 3             (should print error)
    # python your_script.py -1 1 2 3            (should print error)
    # python your_script.py 0 1 2 3             (should print error)
    # python your_script.py abc 1 2 3           (should print error)
    
    print("--- Running with actual command line arguments ---")
    print(f"Output: {get_argument_at_index(sys.argv)}")
    print("------------------------------------------------\n")
    
    print("--- Running with simulated test cases ---")

    # Test Case 1: Valid index
    test1 = ["script.py", "3", "apple", "banana", "cherry"]
    print("Test Case 1: python script.py 3 apple banana cherry")
    print(f"Output: {get_argument_at_index(test1)}") # Expected: banana
    print()

    # Test Case 2: Index out of bounds (too high)
    test2 = ["script.py", "3", "dog", "cat"]
    print("Test Case 2: python script.py 3 dog cat")
    print(f"Output: {get_argument_at_index(test2)}") # Expected: Error
    print()

    # Test Case 3: Invalid index (not a number)
    test3 = ["script.py", "one", "two", "three"]
    print("Test Case 3: python script.py one two three")
    print(f"Output: {get_argument_at_index(test3)}") # Expected: Error
    print()

    # Test Case 4: Invalid index (zero)
    test4 = ["script.py", "0", "a", "b"]
    print("Test Case 4: python script.py 0 a b")
    print(f"Output: {get_argument_at_index(test4)}") # Expected: Error
    print()

    # Test Case 5: Invalid index (negative)
    test5 = ["script.py", "-1", "a", "b"]
    print("Test Case 5: python script.py -1 a b")
    print(f"Output: {get_argument_at_index(test5)}") # Expected: Error
    print()

if __name__ == "__main__":
    main()