# The predefined list
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Takes an index and returns the value at that index in the id_sequence list.
    Performs bounds checking to prevent security vulnerabilities.
    
    Args:
        index: The index of the element to retrieve.
        
    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    # Security check: ensure the index is within the valid bounds of the list.
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        # Return a sentinel value to indicate an error (index out of bounds).
        return -1

# Main block to run test cases
if __name__ == "__main__":
    # 5 test cases
    print("--- Running Test Cases ---")

    # Test Case 1: Valid index in the middle
    index1 = 3
    print(f"Test Case 1: Index = {index1}, Value = {get_value_at_index(index1)}")

    # Test Case 2: Valid index at the beginning
    index2 = 0
    print(f"Test Case 2: Index = {index2}, Value = {get_value_at_index(index2)}")

    # Test Case 3: Valid index at the end
    index3 = len(id_sequence) - 1
    print(f"Test Case 3: Index = {index3}, Value = {get_value_at_index(index3)}")

    # Test Case 4: Invalid index (negative)
    index4 = -1
    print(f"Test Case 4: Index = {index4}, Value = {get_value_at_index(index4)}")

    # Test Case 5: Invalid index (out of bounds)
    index5 = len(id_sequence)
    print(f"Test Case 5: Index = {index5}, Value = {get_value_at_index(index5)}")