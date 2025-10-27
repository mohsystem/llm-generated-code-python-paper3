
array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if index < 0 or index >= len(array):
        raise IndexError(f"Index out of bounds: {index}")
    return array[index]

if __name__ == "__main__":
    # Test case 1
    print(f"Index 0: {get_value_at_index(0)}")
    
    # Test case 2
    print(f"Index 5: {get_value_at_index(5)}")
    
    # Test case 3
    print(f"Index 9: {get_value_at_index(9)}")
    
    # Test case 4
    print(f"Index 3: {get_value_at_index(3)}")
    
    # Test case 5
    print(f"Index 7: {get_value_at_index(7)}")
