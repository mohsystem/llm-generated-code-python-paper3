import sys

def get_element_at_index(data, args):
    """
    Finds and returns an element from a list based on a string index argument.
    It handles parsing and validation of the index.

    Args:
        data: The list of elements to access.
        args: A list of string arguments (like sys.argv), where args[1] is the index.
    
    Returns:
        The element at the specified index, or an error message string.
    """
    # 1. Security Check: Ensure an argument is provided.
    # Note: args[0] is the script name, so we need at least 2 elements.
    if len(args) < 2:
        return "Error: No index provided.\nUsage: please provide an integer index as an argument."

    arg = args[1]
    
    # 2. Security Check: Ensure the argument is a valid integer.
    try:
        index = int(arg)
    except ValueError:
        return f"Error: Argument '{arg}' is not a valid integer."

    # 3. Security Check: Ensure the index is within the list bounds.
    if not (0 <= index < len(data)):
        return f"Error: Index {index} is out of bounds. Must be between 0 and {len(data) - 1}."

    # If all checks pass, return the element.
    return f"Element at index {index}: {data[index]}"


def main():
    """
    Main function to run test cases.
    """
    data = ["Apple", "Banana", "Cherry", "Date", "Elderberry"]

    print("--- Running 5 Test Cases ---")
    
    # Test Case 1: Valid index
    # We add a placeholder for script name at args[0]
    print(f"Test Case 1 (Input: \"2\"): {get_element_at_index(data, ['script.py', '2'])}")

    # Test Case 2: Out-of-bounds index (too high)
    print(f"Test Case 2 (Input: \"10\"): {get_element_at_index(data, ['script.py', '10'])}")

    # Test Case 3: Out-of-bounds index (negative)
    print(f"Test Case 3 (Input: \"-1\"): {get_element_at_index(data, ['script.py', '-1'])}")

    # Test Case 4: Non-numeric input
    print(f"Test Case 4 (Input: \"abc\"): {get_element_at_index(data, ['script.py', 'abc'])}")

    # Test Case 5: No input
    print(f"Test Case 5 (Input: empty): {get_element_at_index(data, ['script.py'])}")

    print("\n--- Testing with actual command-line arguments ---")
    # This part will use the actual arguments passed when running the program
    if len(sys.argv) > 1:
        print(f"Actual command-line input: {sys.argv[1:]}")
        print(get_element_at_index(data, sys.argv))
    else:
        print("No actual command-line arguments provided. Run like 'python your_script.py 3'")

if __name__ == "__main__":
    main()