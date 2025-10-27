
import sys

def getValueFromArray(array, size, index):
    # Secure: Check if index is within valid bounds
    if array is None or index < 0 or index >= size or index >= len(array):
        return -1  # Return error code for invalid access
    return array[index]

def main():
    # Test case 1: Valid index in middle
    test1 = [10, 20, 30, 40, 50]
    result1 = getValueFromArray(test1, 5, 2)
    print(f"Test 1 - Expected: 30, Got: {result1}")
    
    # Test case 2: Valid index at start
    test2 = [5, 15, 25, 35]
    result2 = getValueFromArray(test2, 4, 0)
    print(f"Test 2 - Expected: 5, Got: {result2}")
    
    # Test case 3: Valid index at end
    test3 = [100, 200, 300]
    result3 = getValueFromArray(test3, 3, 2)
    print(f"Test 3 - Expected: 300, Got: {result3}")
    
    # Test case 4: Invalid index (out of bounds)
    test4 = [1, 2, 3]
    result4 = getValueFromArray(test4, 3, 5)
    print(f"Test 4 - Expected: -1 (error), Got: {result4}")
    
    # Test case 5: Invalid index (negative)
    test5 = [7, 8, 9, 10]
    result5 = getValueFromArray(test5, 4, -1)
    print(f"Test 5 - Expected: -1 (error), Got: {result5}")
    
    sys.exit(result1)

if __name__ == "__main__":
    main()
