
id_sequence = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]

def get_value_at_index(index):
    """Returns value at given index with bounds checking"""
    if not isinstance(index, int):
        print("Error: Index must be an integer")
        return None
    
    if index < 0 or index >= len(id_sequence):
        print(f"Error: Index out of bounds. Valid range: 0-{len(id_sequence) - 1}")
        return None
    
    return id_sequence[index]

def get_user_input_and_get_value():
    """Prompts user for index and returns corresponding value"""
    try:
        index = int(input(f"Enter an index value (0-{len(id_sequence) - 1}): "))
        return get_value_at_index(index)
    except ValueError:
        print("Error: Invalid input. Please enter a valid integer.")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

if __name__ == "__main__":
    # Test case 1: Valid index at beginning
    print(f"Test 1 - Index 0: {get_value_at_index(0)}")
    
    # Test case 2: Valid index in middle
    print(f"Test 2 - Index 5: {get_value_at_index(5)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 - Index 9: {get_value_at_index(9)}")
    
    # Test case 4: Invalid negative index
    print(f"Test 4 - Index -1: {get_value_at_index(-1)}")
    
    # Test case 5: Invalid index beyond bounds
    print(f"Test 5 - Index 15: {get_value_at_index(15)}")
