
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if index < 0 or index >= len(id_sequence):
        return None  # Return None for out of bounds index
    return id_sequence[index]

if __name__ == "__main__":
    # Test case 1: Valid index at beginning
    print(f"Test 1 (index 0): {get_value_at_index(0)}")
    
    # Test case 2: Valid index in middle
    print(f"Test 2 (index 4): {get_value_at_index(4)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 (index 9): {get_value_at_index(9)}")
    
    # Test case 4: Invalid negative index
    print(f"Test 4 (index -1): {get_value_at_index(-1)}")
    
    # Test case 5: Invalid index beyond array length
    print(f"Test 5 (index 15): {get_value_at_index(15)}")
