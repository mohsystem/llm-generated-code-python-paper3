
def get_value_at_index(index, array):
    if index < 0 or index >= len(array):
        raise IndexError("Index out of bounds")
    return array[index]

def main():
    test_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    # Test case 1: Valid index at beginning
    try:
        print(f"Test 1 - Index 0: {get_value_at_index(0, test_array)}")
    except Exception as e:
        print(f"Test 1 Error: {e}")
    
    # Test case 2: Valid index in middle
    try:
        print(f"Test 2 - Index 5: {get_value_at_index(5, test_array)}")
    except Exception as e:
        print(f"Test 2 Error: {e}")
    
    # Test case 3: Valid index at end
    try:
        print(f"Test 3 - Index 9: {get_value_at_index(9, test_array)}")
    except Exception as e:
        print(f"Test 3 Error: {e}")
    
    # Test case 4: Invalid negative index
    try:
        print(f"Test 4 - Index -1: {get_value_at_index(-1, test_array)}")
    except Exception as e:
        print(f"Test 4 Error: {e}")
    
    # Test case 5: Invalid index beyond array length
    try:
        print(f"Test 5 - Index 15: {get_value_at_index(15, test_array)}")
    except Exception as e:
        print(f"Test 5 Error: {e}")

if __name__ == "__main__":
    main()
