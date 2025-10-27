
import sys

def getValueFromArray(array, size, index):
    # Validate parameters to prevent security vulnerabilities
    if array is None:
        return -1
    
    # Validate index is within valid bounds to prevent buffer overflow
    if index < 0 or index >= size or index >= len(array):
        return -1
    
    return array[index]

def main():
    # Define the id_sequence array
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)
    
    # Test cases
    print("Test Case 1 - Index 0:", getValueFromArray(id_sequence, size, 0))
    print("Test Case 2 - Index 5:", getValueFromArray(id_sequence, size, 5))
    print("Test Case 3 - Index 9:", getValueFromArray(id_sequence, size, 9))
    print("Test Case 4 - Index -1 (invalid):", getValueFromArray(id_sequence, size, -1))
    print("Test Case 5 - Index 15 (out of bounds):", getValueFromArray(id_sequence, size, 15))
    
    # Read input from user
    try:
        index = int(input("Enter an index: "))
        result = getValueFromArray(id_sequence, size, index)
        sys.exit(result if result >= 0 else 1)
    except ValueError:
        sys.exit(1)
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
