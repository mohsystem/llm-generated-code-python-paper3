# The predefined array (list in Python)
an_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Returns the value at the specified index of the predefined array.

    Args:
        index: The index of the element to return.

    Returns:
        The element at the specified index, or -1 if the index is out of bounds.
    """
    # Check if the index is within the valid range
    if 0 <= index < len(an_array):
        return an_array[index]
    else:
        # Return a special value to indicate an invalid index
        return -1

def main():
    # 5 Test Cases
    print(f"Test Case 1 (index = 3): {get_value_at_index(3)}")
    print(f"Test Case 2 (index = 0): {get_value_at_index(0)}")
    print(f"Test Case 3 (index = 9): {get_value_at_index(9)}")
    print(f"Test Case 4 (index = 10): {get_value_at_index(10)}")  # Out of bounds
    print(f"Test Case 5 (index = -1): {get_value_at_index(-1)}")  # Out of bounds

if __name__ == "__main__":
    main()