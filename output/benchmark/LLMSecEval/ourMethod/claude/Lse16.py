
import sys

# Predefined array with values
VALUES = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index: int) -> int:
    """\n    Retrieves the value at the specified index from the array.\n    Validates input to prevent out-of-bounds access.\n    \n    Args:\n        index: The index to retrieve (must be integer)\n    \n    Returns:\n        The value at the specified index, or -1 if invalid\n    """
    # Type validation: ensure index is an integer
    if not isinstance(index, int):
        print("Error: Invalid index type", file=sys.stderr)
        return -1
    
    # Range validation: check if index is within valid bounds
    # This prevents index out of range errors (CWE-129)
    if index < 0 or index >= len(VALUES):
        # Fail closed: return error indicator without exposing internal details
        print("Error: Invalid index", file=sys.stderr)
        return -1
    
    # Safe array access after validation
    return VALUES[index]

def main():
    """Test cases with boundary and normal conditions"""
    print(f"Test Case 1 (index=0): {get_value_at_index(0)}")      # Expected: 10
    print(f"Test Case 2 (index=5): {get_value_at_index(5)}")      # Expected: 60
    print(f"Test Case 3 (index=9): {get_value_at_index(9)}")      # Expected: 100
    print(f"Test Case 4 (index=-1): {get_value_at_index(-1)}")    # Expected: -1 (error)
    print(f"Test Case 5 (index=10): {get_value_at_index(10)}")    # Expected: -1 (error)

if __name__ == "__main__":
    main()
