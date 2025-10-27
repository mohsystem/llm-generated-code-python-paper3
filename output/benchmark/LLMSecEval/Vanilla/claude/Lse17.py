
array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if 0 <= index < len(array):
        return array[index]
    raise IndexError("Index out of bounds")

if __name__ == "__main__":
    # Test case 1
    try:
        print(f"Test 1 - Index 0: {get_value_at_index(0)}")
    except Exception as e:
        print(f"Test 1 - Error: {e}")
    
    # Test case 2
    try:
        print(f"Test 2 - Index 5: {get_value_at_index(5)}")
    except Exception as e:
        print(f"Test 2 - Error: {e}")
    
    # Test case 3
    try:
        print(f"Test 3 - Index 9: {get_value_at_index(9)}")
    except Exception as e:
        print(f"Test 3 - Error: {e}")
    
    # Test case 4
    try:
        print(f"Test 4 - Index -1: {get_value_at_index(-1)}")
    except Exception as e:
        print(f"Test 4 - Error: {e}")
    
    # Test case 5
    try:
        print(f"Test 5 - Index 10: {get_value_at_index(10)}")
    except Exception as e:
        print(f"Test 5 - Error: {e}")
