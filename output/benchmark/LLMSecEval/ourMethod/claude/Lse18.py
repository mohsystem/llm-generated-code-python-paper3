
# Predefined array for demonstration
DATA_ARRAY = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index: int) -> int:
    """\n    Returns the value at the specified index in the array.\n    Validates input to prevent out-of-bounds access.\n    \n    Args:\n        index: The index to retrieve from the array\n        \n    Returns:\n        The value at the specified index, or -1 if invalid\n    """
    # Input validation: Check type to prevent type confusion attacks
    if not isinstance(index, int):
        # Fail closed: reject non-integer inputs
        return -1
    
    # Input validation: Check if index is within valid bounds
    # This prevents IndexError and invalid memory access
    if index < 0 or index >= len(DATA_ARRAY):
        # Fail closed: return error indicator without exposing internal details
        return -1
    
    # Safe array access after validation
    return DATA_ARRAY[index]

def main():
    """Main function with test cases"""
    # Test case 1: Valid index at beginning
    result1 = get_value_at_index(0)
    print(f"Test 1 - Index 0: {result1}")
    
    # Test case 2: Valid index in middle
    result2 = get_value_at_index(5)
    print(f"Test 2 - Index 5: {result2}")
    
    # Test case 3: Valid index at end
    result3 = get_value_at_index(9)
    print(f"Test 3 - Index 9: {result3}")
    
    # Test case 4: Invalid negative index
    result4 = get_value_at_index(-1)
    print(f"Test 4 - Index -1: {result4}")
    
    # Test case 5: Invalid index beyond array bounds
    result5 = get_value_at_index(15)
    print(f"Test 5 - Index 15: {result5}")

if __name__ == "__main__":
    main()
