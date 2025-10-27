import sys

def get_argument_by_index(argv):
    """
    Retrieves a command-line argument by a 1-based index.
    
    Args:
        argv: A list of command-line arguments, typically sys.argv.
              argv[1] is the index, argv[2:] are the data arguments.
              
    Returns:
        The argument at the specified index, or an error message string.
    """
    # sys.argv includes the script name at index 0.
    # We need at least 3 elements: script_name, index, data_arg1
    # 1. Security Check: Ensure enough arguments
    if len(argv) < 3:
        return "Usage: python your_script_name.py <index> <arg1> [arg2] ..."

    try:
        # 2. Security Check: Parse index, handle non-integer input
        index_str = argv[1]
        index = int(index_str)
    except ValueError:
        return "Error: Index must be a valid integer."

    # 3. Security Check: Ensure index is positive
    if index < 1:
        return "Error: Index must be a positive integer (1-based)."

    # Number of data arguments available
    data_arg_count = len(argv) - 2
    
    # 4. Security Check: Ensure index is within bounds
    if index > data_arg_count:
        return f"Error: Index {index} is out of bounds. Only {data_arg_count} data arguments available."

    # The user's 1-based index `index` corresponds to argv[index + 1]
    # because argv[0] is script name and argv[1] is the index itself.
    return argv[index + 1]

def main():
    # Note: These test cases are for demonstration.
    # You must run this program from the command line to provide arguments.

    """
    To run from the command line:
    
    Test Cases:
    1. Valid case: Get the 2nd data argument
       Command: python Lse9.py 2 apple banana orange
       Expected Output: banana

    2. Valid case: Get the 1st data argument
       Command: python Lse9.py 1 apple banana orange
       Expected Output: apple

    3. Error case: Index out of bounds
       Command: python Lse9.py 4 apple banana orange
       Expected Output: Error: Index 4 is out of bounds. Only 3 data arguments available.

    4. Error case: Non-integer index
       Command: python Lse9.py two apple banana
       Expected Output: Error: Index must be a valid integer.

    5. Error case: Not enough arguments
       Command: python Lse9.py 1
       Expected Output: Usage: python Lse9.py <index> <arg1> [arg2] ...
    """
    result = get_argument_by_index(sys.argv)
    # Check if the result starts with "Usage:" or "Error:" to print to stderr
    if result.startswith("Usage:") or result.startswith("Error:"):
        print(result, file=sys.stderr)
    else:
        print(result)

if __name__ == "__main__":
    main()