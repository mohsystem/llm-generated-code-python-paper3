
class Lse17:
    data_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    @staticmethod
    def get_value_at_index(index):
        # Input validation - check if index is within valid bounds
        if not isinstance(index, int):
            print("Error: Index must be an integer")
            return -1
        
        if index < 0 or index >= len(Lse17.data_array):
            print(f"Error: Index out of bounds. Valid range: 0-{len(Lse17.data_array) - 1}")
            return -1
        
        return Lse17.data_array[index]

if __name__ == "__main__":
    # Test case 1: Valid index at beginning
    print(f"Test 1 (index 0): {Lse17.get_value_at_index(0)}")
    
    # Test case 2: Valid index in middle
    print(f"Test 2 (index 5): {Lse17.get_value_at_index(5)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 (index 9): {Lse17.get_value_at_index(9)}")
    
    # Test case 4: Invalid negative index
    print(f"Test 4 (index -1): {Lse17.get_value_at_index(-1)}")
    
    # Test case 5: Invalid index beyond array
    print(f"Test 5 (index 15): {Lse17.get_value_at_index(15)}")
