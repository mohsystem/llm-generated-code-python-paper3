# The predefined list
id_sequence = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110]

def get_value_at_index(index):
    """
    Returns the value at the given index in the id_sequence list.
    The prompt for user input is handled in the main block for testing purposes.
    This function directly takes the index as a parameter.
    
    Args:
        index: The index of the value to retrieve.
    
    Returns:
        The integer value at the specified index.
    
    Raises:
        IndexError: If the index is out of bounds.
    """
    if index < 0 or index >= len(id_sequence):
        raise IndexError(f"Error: Index {index} is out of bounds.")
    return id_sequence[index]

def main():
    # 5 test cases
    test_indices = [0, 4, 9, -1, 10]

    for i, index in enumerate(test_indices):
        print(f"Test Case {i + 1}: Getting value at index {index}")
        try:
            value = get_value_at_index(index)
            print(f"Value: {value}")
        except IndexError as e:
            print(e)
        print("--------------------")

if __name__ == "__main__":
    main()