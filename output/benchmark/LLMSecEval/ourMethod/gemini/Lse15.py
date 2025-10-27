import sys

# Define a constant sequence of IDs.
ID_SEQUENCE = (101, 102, 103, 104, 105, 106, 107, 108, 109, 110)

def get_value_at_index(index: int) -> int:
    """
    Returns the value at a given index in the ID_SEQUENCE tuple.
    This function demonstrates secure coding by validating the index to prevent
    out-of-bounds access.

    Args:
        index: The index of the value to retrieve.

    Returns:
        The integer value at the specified index.

    Raises:
        TypeError: if the index is not an integer.
        IndexError: if the index is out of the valid range.
    """
    # Rule #4: Validate input type.
    if not isinstance(index, int):
        raise TypeError("Error: Index must be an integer.")
    
    # Rules #1, #2, #4: Ensure that the index is within the buffer's boundaries.
    if 0 <= index < len(ID_SEQUENCE):
        return ID_SEQUENCE[index]
    else:
        # Rule #5, #7: Use appropriate exception for errors.
        raise IndexError(f"Error: Index {index} is out of bounds.")

def run_test_case(test_name: str, index):
    """Helper function to run a single test case and print the result."""
    print(f"{test_name} with index {index}: ", end="")
    try:
        value = get_value_at_index(index)
        print(f"Success! Value is {value}")
    except (IndexError, TypeError) as e:
        print(e, file=sys.stderr)

def main():
    """Main function to run test cases and get user input."""
    print("--- Running 5 Test Cases ---")
    
    # Test cases dictionary: Test Name -> Index to test
    test_cases = {
        "Test Case 1": 0,    # Valid index (start)
        "Test Case 2": 5,    # Valid index (middle)
        "Test Case 3": len(ID_SEQUENCE) - 1, # Valid index (end)
        "Test Case 4": -1,   # Invalid index (negative)
        "Test Case 5": len(ID_SEQUENCE) # Invalid index (out of bounds)
    }

    for name, index in test_cases.items():
        run_test_case(name, index)
    
    # The prompt "The function first prompts the user for an index value" is interpreted
    # as the main application logic prompting the user before calling the function.
    print("\n--- Interactive User Test ---")
    try:
        user_input = input("Please enter an index value: ")
        # Rule #4: Validate input can be converted to an integer.
        user_index = int(user_input)
        value = get_value_at_index(user_index)
        print(f"The value at index {user_index} is: {value}")
    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
    except (IndexError, TypeError) as e:
        print(e, file=sys.stderr)

if __name__ == "__main__":
    main()