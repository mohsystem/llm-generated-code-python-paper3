import sys

def print_arg_by_index(argv):
    """
    Prints a command-line argument based on a given index.
    The index is provided as the first argument after the script name,
    and it refers to the subsequent arguments.
    """
    # sys.argv includes the script name at argv[0].
    # We need at least 3 items: script name, index, and one argument value.
    if len(argv) < 3:
        print("Usage: python", argv[0] if argv else "Lse9.py", "<index> <arg1> <arg2> ...")
        return

    try:
        # The first user argument (argv[1]) is the user-provided index.
        user_index = int(argv[1])

        if user_index <= 0:
            print("Error: Index must be a positive integer.")
            return

        # The target argument is at index `user_index + 1` because
        # argv[0] is the script name and argv[1] is the index itself.
        target_index = user_index + 1

        if len(argv) > target_index:
            print(argv[target_index])
        else:
            print(f"Error: Index {user_index} is out of bounds for the provided arguments.")

    except ValueError:
        print("Error: The first argument must be a valid integer index.")

def main():
    """
    To run the test cases, save the code as a .py file (e.g., Lse9.py)
    and execute from the command line:

    Test Case 1: Get the 1st argument after the index
    Command: python Lse9.py 1 apple banana cherry
    Expected Output: apple

    Test Case 2: Get the 3rd argument after the index
    Command: python Lse9.py 3 apple banana cherry
    Expected Output: cherry

    Test Case 3: Index out of bounds
    Command: python Lse9.py 4 apple banana cherry
    Expected Output: Error: Index 4 is out of bounds for the provided arguments.

    Test Case 4: Not enough arguments (no argument to select)
    Command: python Lse9.py 1
    Expected Output: Usage: python Lse9.py <index> <arg1> <arg2> ...

    Test Case 5: Invalid index (not an integer)
    Command: python Lse9.py hello world
    Expected Output: Error: The first argument must be a valid integer index.
    """
    print_arg_by_index(sys.argv)

if __name__ == "__main__":
    main()