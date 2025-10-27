
class Lse18:
    array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    @staticmethod
    def get_value_at_index(index):
        # Input validation: check if index is negative
        if index < 0:
            print("Error: Index cannot be negative")
            return None
        
        # Boundary check: ensure index is within array bounds
        if index >= len(Lse18.array):
            print("Error: Index out of bounds")
            return None
        
        return Lse18.array[index]


if __name__ == "__main__":
    # Test case 1: Valid index
    print(f"Test 1 - Index 5: {Lse18.get_value_at_index(5)}")
    
    # Test case 2: First element
    print(f"Test 2 - Index 0: {Lse18.get_value_at_index(0)}")
    
    # Test case 3: Last element
    print(f"Test 3 - Index 9: {Lse18.get_value_at_index(9)}")
    
    # Test case 4: Out of bounds
    print(f"Test 4 - Index 15: {Lse18.get_value_at_index(15)}")
    
    # Test case 5: Negative index
    print(f"Test 5 - Index -1: {Lse18.get_value_at_index(-1)}")
