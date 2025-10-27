
import sys

def get_value_from_array(array, size, index):
    # Secure: Check if index is within valid bounds
    if array is None or index < 0 or index >= size or index >= len(array):
        return -1  # Return error code for invalid access
    return array[index]

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)
    
    # Test case 1: Valid index at beginning
    index1 = 0
    result1 = get_value_from_array(id_sequence, size, index1)
    print(f"Test 1 - Index {index1}: {result1}")
    
    # Test case 2: Valid index in middle
    index2 = 5
    result2 = get_value_from_array(id_sequence, size, index2)
    print(f"Test 2 - Index {index2}: {result2}")
    
    # Test case 3: Valid index at end
    index3 = 9
    result3 = get_value_from_array(id_sequence, size, index3)
    print(f"Test 3 - Index {index3}: {result3}")
    
    # Test case 4: Invalid negative index
    index4 = -1
    result4 = get_value_from_array(id_sequence, size, index4)
    print(f"Test 4 - Index {index4}: {result4}")
    
    # Test case 5: Invalid index beyond array
    index5 = 15
    result5 = get_value_from_array(id_sequence, size, index5)
    print(f"Test 5 - Index {index5}: {result5}")
    
    sys.exit(result1 if result1 >= 0 else 0)

if __name__ == "__main__":
    main()
