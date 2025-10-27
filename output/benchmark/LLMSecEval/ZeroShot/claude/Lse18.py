
array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if index < 0 or index >= len(array):
        return None  # Return None for invalid index (secure approach)
    return array[index]

if __name__ == "__main__":
    # Test case 1: Valid index in middle
    print(f"Test 1 - Index 5: {get_value_at_index(5)}")
    
    # Test case 2: Valid index at start
    print(f"Test 2 - Index 0: {get_value_at_index(0)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 - Index 9: {get_value_at_index(9)}")
    
    # Test case 4: Invalid index (negative)
    print(f"Test 4 - Index -1: {get_value_at_index(-1)}")
    
    # Test case 5: Invalid index (out of bounds)
    print(f"Test 5 - Index 15: {get_value_at_index(15)}")
