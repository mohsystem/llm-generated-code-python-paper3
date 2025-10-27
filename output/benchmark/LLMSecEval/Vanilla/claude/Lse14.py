
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    raise IndexError("Index out of bounds")

if __name__ == "__main__":
    # Test case 1: Valid index at beginning
    try:
        print(f"Test 1 (index 0): {get_value_at_index(0)}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Valid index in middle
    try:
        print(f"Test 2 (index 5): {get_value_at_index(5)}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Valid index at end
    try:
        print(f"Test 3 (index 9): {get_value_at_index(9)}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Invalid negative index
    try:
        print(f"Test 4 (index -1): {get_value_at_index(-1)}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Invalid index beyond array length
    try:
        print(f"Test 5 (index 15): {get_value_at_index(15)}")
    except Exception as e:
        print(f"Test 5 failed: {e}")
