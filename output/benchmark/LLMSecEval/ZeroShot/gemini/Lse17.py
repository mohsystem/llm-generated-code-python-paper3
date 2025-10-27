# Predefined data list
DATA = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(data_list, index):
    """
    Securely retrieves the value at a given index from a list.
    This function performs bounds checking to prevent out-of-bounds access.

    Args:
        data_list (list): The list to access.
        index (int): The index of the element to retrieve.

    Returns:
        int: The integer value at the specified index.

    Raises:
        IndexError: If the index is out of the valid range.
    """
    # Secure: Check if the index is within the valid bounds of the list.
    if 0 <= index < len(data_list):
        return data_list[index]
    else:
        # If the index is invalid, raise an exception to signal the error.
        raise IndexError(f"Error: Index {index} is out of bounds.")

def main():
    """Main function with 5 test cases."""
    # 5 Test Cases: 3 valid, 2 invalid
    test_indexes = [3, 0, 9, -1, 10]

    print("--- Python: Testing get_value_at_index ---")
    for index in test_indexes:
        try:
            value = get_value_at_index(DATA, index)
            print(f"Test Case: index = {index}")
            print(f"  -> Success: Value is {value}")
        except IndexError as e:
            print(f"Test Case: index = {index}")
            print(f"  -> {e}")
        print("----------------------------------------")

if __name__ == "__main__":
    main()