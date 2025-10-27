
import sys

def getValueFromArray(array, size, index):
    if 0 <= index < size:
        return array[index]
    return -1  # Return -1 for invalid index

if __name__ == "__main__":
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)
    
    # Test case 1: Valid index 0
    index1 = 0
    result1 = getValueFromArray(id_sequence, size, index1)
    print(f"Test 1 - Index {index1}: {result1}")
    
    # Test case 2: Valid index 5
    index2 = 5
    result2 = getValueFromArray(id_sequence, size, index2)
    print(f"Test 2 - Index {index2}: {result2}")
    
    # Test case 3: Valid index 9 (last element)
    index3 = 9
    result3 = getValueFromArray(id_sequence, size, index3)
    print(f"Test 3 - Index {index3}: {result3}")
    
    # Test case 4: Invalid index -1
    index4 = -1
    result4 = getValueFromArray(id_sequence, size, index4)
    print(f"Test 4 - Index {index4}: {result4}")
    
    # Test case 5: Invalid index 10 (out of bounds)
    index5 = 10
    result5 = getValueFromArray(id_sequence, size, index5)
    print(f"Test 5 - Index {index5}: {result5}")
    
    sys.exit(result1)
