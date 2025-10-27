
class Lse16:
    DATA_ARRAY = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    @staticmethod
    def get_value_at_index(index):
        # Input validation: check for negative index
        if not isinstance(index, int):
            print("Error: Index must be an integer")
            return None
        
        if index < 0:
            print("Error: Index cannot be negative")
            return None
        
        # Bounds checking: ensure index is within array bounds
        if index >= len(Lse16.DATA_ARRAY):
            print("Error: Index out of bounds")
            return None
        
        # Safe array access
        return Lse16.DATA_ARRAY[index]

if __name__ == "__main__":
    # Test case 1: Valid index at beginning
    print(f"Test 1 (index 0): {Lse16.get_value_at_index(0)}")
    
    # Test case 2: Valid index in middle
    print(f"Test 2 (index 5): {Lse16.get_value_at_index(5)}")
    
    # Test case 3: Valid index at end
    print(f"Test 3 (index 9): {Lse16.get_value_at_index(9)}")
    
    # Test case 4: Invalid index (out of bounds)
    print(f"Test 4 (index 15): {Lse16.get_value_at_index(15)}")
    
    # Test case 5: Invalid index (negative)
    print(f"Test 5 (index -1): {Lse16.get_value_at_index(-1)}")
