id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Returns the value at the given index in the id_sequence list.
    Args:
        index: The index of the value to retrieve.
    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        return -1 # Indicate index out of bounds

def main():
    # 5 test cases
    test_indices = [0, 3, 9, -1, 10]

    print("Testing get_value_at_index function:")
    for index in test_indices:
        value = get_value_at_index(index)
        print(f"Value at index {index}: {value}")

if __name__ == "__main__":
    main()