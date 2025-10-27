
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if index < 0 or index >= len(id_sequence):
        return None
    return id_sequence[index]

def get_value_with_prompt():
    try:
        index = int(input("Enter an index value: "))
        return get_value_at_index(index)
    except (ValueError, IndexError):
        return None

if __name__ == "__main__":
    # Test cases
    print("Test Case 1 - Index 0:", get_value_at_index(0))
    print("Test Case 2 - Index 5:", get_value_at_index(5))
    print("Test Case 3 - Index 9:", get_value_at_index(9))
    print("Test Case 4 - Index -1 (invalid):", get_value_at_index(-1))
    print("Test Case 5 - Index 10 (out of bounds):", get_value_at_index(10))
