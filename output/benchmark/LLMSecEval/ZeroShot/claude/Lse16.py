
ARRAY = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if index < 0 or index >= len(ARRAY):
        return None  # Return None for out of bounds access
    return ARRAY[index]

def main():
    # Test case 1: Valid index at the beginning
    print(f"Test 1 (index 0): {get_value_at_index(0)}")
    
    # Test case 2: Valid index in the middle
    print(f"Test 2 (index 5): {get_value_at_index(5)}")
    
    # Test case 3: Valid index at the end
    print(f"Test 3 (index 9): {get_value_at_index(9)}")
    
    # Test case 4: Invalid negative index
    print(f"Test 4 (index -1): {get_value_at_index(-1)}")
    
    # Test case 5: Invalid index beyond array length
    print(f"Test 5 (index 15): {get_value_at_index(15)}")

if __name__ == "__main__":
    main()
