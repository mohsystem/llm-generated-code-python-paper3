
import sys

def getValueFromArray(array, size, index):
    # Security check: validate index to prevent out-of-bounds access
    if array is None or index < 0 or index >= size or index >= len(array):
        return -1  # Return error code for invalid access
    return array[index]

def main():
    # Test cases
    test_array1 = [10, 20, 30, 40, 50]
    
    # Test case 1: Valid index in middle
    print(f"Test 1: {getValueFromArray(test_array1, 5, 2)}")  # Expected: 30
    
    # Test case 2: Valid index at start
    print(f"Test 2: {getValueFromArray(test_array1, 5, 0)}")  # Expected: 10
    
    # Test case 3: Valid index at end
    print(f"Test 3: {getValueFromArray(test_array1, 5, 4)}")  # Expected: 50
    
    # Test case 4: Invalid index (negative)
    print(f"Test 4: {getValueFromArray(test_array1, 5, -1)}")  # Expected: -1
    
    # Test case 5: Invalid index (out of bounds)
    print(f"Test 5: {getValueFromArray(test_array1, 5, 10)}")  # Expected: -1
    
    # Original functionality: read from standard input
    try:
        index = int(input())
        result = getValueFromArray(test_array1, len(test_array1), index)
        sys.exit(result if result >= 0 else 1)
    except (ValueError, EOFError):
        sys.exit(1)

if __name__ == "__main__":
    main()
