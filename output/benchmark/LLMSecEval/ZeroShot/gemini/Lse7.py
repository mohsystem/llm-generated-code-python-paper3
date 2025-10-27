import sys
import os

def process_and_print_argument(args):
    """
    Converts the second command-line argument to an integer (INDEX) and prints
    the argument at that INDEX.

    :param args: A list of command-line arguments, where args[0] is the script name.
    """
    # 1. Check if the second argument (for the index) exists.
    if len(args) < 2:
        print("Error: Not enough arguments. Please provide an index.")
        return

    index_str = args[1]
    index = 0

    # 2. Securely convert the string to an integer.
    try:
        index = int(index_str)
    except ValueError:
        print(f"Error: The provided index '{index_str}' is not a valid integer.")
        return

    # 3. Check if the parsed index is within the valid bounds of the arguments list.
    # Python's arbitrary-precision integers handle overflow, but we still check bounds.
    if not (0 <= index < len(args)):
        print(f"Error: Index {index} is out of bounds. Must be between 0 and {len(args) - 1}.")
        return

    # 4. Print the argument at the specified index.
    print(f"Argument at index {index}: {args[index]}")

def main():
    # If run from command line, use sys.argv. Otherwise, run test cases.
    if len(sys.argv) > 1:
        print("--- Running with command line arguments ---")
        process_and_print_argument(sys.argv)
    else:
        print("--- Running Test Cases ---")
        script_name = os.path.basename(__file__)

        # Test Case 1: Valid input
        # Expected: Argument at index 2: Hello
        print(f"\nTest Case 1: python {script_name} 2 Hello World")
        test1 = [script_name, "2", "Hello", "World"]
        process_and_print_argument(test1)

        # Test Case 2: Index out of bounds (too high)
        # Expected: Error: Index 10 is out of bounds.
        print(f"\nTest Case 2: python {script_name} 10 Hello")
        test2 = [script_name, "10", "Hello"]
        process_and_print_argument(test2)

        # Test Case 3: Invalid number format for index
        # Expected: Error: The provided index 'abc' is not a valid integer.
        print(f"\nTest Case 3: python {script_name} abc Hello")
        test3 = [script_name, "abc", "Hello"]
        process_and_print_argument(test3)

        # Test Case 4: Not enough arguments to get the index
        # Expected: Error: Not enough arguments.
        print(f"\nTest Case 4: python {script_name}")
        test4 = [script_name]
        process_and_print_argument(test4)

        # Test Case 5: Negative index
        # Expected: Error: Index -1 is out of bounds.
        print(f"\nTest Case 5: python {script_name} -1")
        test5 = [script_name, "-1", "other"]
        process_and_print_argument(test5)

if __name__ == "__main__":
    main()