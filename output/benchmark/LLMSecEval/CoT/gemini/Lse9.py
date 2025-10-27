import sys

def get_argument_by_index(argv):
    """
    Takes a list of command-line arguments (including script name),
    parses the first argument as an index, and returns the argument at that index.
    
    Args:
        argv: A list of strings from sys.argv.
    
    Returns:
        The argument at the specified index or an error message.
    """
    # argv[0] is the script name. Need at least argv[1] (the index).
    if len(argv) < 2:
        return "Error: No index provided. Usage: python your_script.py <index> [args...]"

    index_str = argv[1]
    try:
        index = int(index_str)
    except ValueError:
        return f"Error: Invalid index '{index_str}'. Index must be an integer."

    # The user-provided index N corresponds to argv[N].
    # We must check if this index is valid for the argv list.
    if 0 <= index < len(argv):
        return argv[index]
    else:
        return f"Error: Index {index} is out of bounds for arguments list of size {len(argv)}."

if __name__ == "__main__":
    # This program processes actual command-line arguments.
    # The following comments show 5 test cases and how to run them from the terminal.

    """
    To run:
    python your_script_name.py <args>

    --- Test Cases ---

    1. Normal Case: Get the argument at index 3.
       Command: python your_script_name.py 3 apple banana cherry
       Expected Output: cherry
       (argv is ['your_script_name.py', '3', 'apple', 'banana', 'cherry'], argv[3] is 'cherry')

    2. Edge Case (Program Name): Get the argument at index 0.
       Command: python your_script_name.py 0 apple banana
       Expected Output: your_script_name.py

    3. Error Case (Index Out of Bounds): Index is too high.
       Command: python your_script_name.py 5 apple banana
       Expected Output: Error: Index 5 is out of bounds for arguments list of size 4.

    4. Error Case (Invalid Index): Index is not a number.
       Command: python your_script_name.py foo apple banana
       Expected Output: Error: Invalid index 'foo'. Index must be an integer.

    5. Error Case (Index points to itself): Get the argument at index 1.
       Command: python your_script_name.py 1 apple banana
       Expected Output: 1
    """
    
    print(get_argument_by_index(sys.argv))