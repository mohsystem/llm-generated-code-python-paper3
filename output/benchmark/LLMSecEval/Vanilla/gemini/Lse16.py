def get_value_at_index(arr, index):
    """
    Returns the value at a given index in a list.
    
    Args:
        arr: The input list.
        index: The index of the element to retrieve.
        
    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    if 0 <= index < len(arr):
        return arr[index]
    else:
        # Return a sentinel value to indicate the index is out of bounds
        return -1

if __name__ == "__main__":
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # 5 test cases
    print(f"Test Case 1 (index 0): {get_value_at_index(data, 0)}")
    print(f"Test Case 2 (index 5): {get_value_at_index(data, 5)}")
    print(f"Test Case 3 (index 9): {get_value_at_index(data, 9)}")
    print(f"Test Case 4 (index -1): {get_value_at_index(data, -1)}")
    print(f"Test Case 5 (index 10): {get_value_at_index(data, 10)}")