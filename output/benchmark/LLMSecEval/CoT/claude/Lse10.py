
import sys

def get_value_from_array(array, size, index):
    # Security: Validate index to prevent out-of-bounds access
    if array is None or index < 0 or index >= size or index >= len(array):
        return -1  # Return error code for invalid access
    return array[index]

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)
    
    # Test cases
    print("Test Case 1 (index 0):", get_value_from_array(id_sequence, size, 0))
    print("Test Case 2 (index 5):", get_value_from_array(id_sequence, size, 5))
    print("Test Case 3 (index 9):", get_value_from_array(id_sequence, size, 9))
    print("Test Case 4 (index -1):", get_value_from_array(id_sequence, size, -1))
    print("Test Case 5 (index 15):", get_value_from_array(id_sequence, size, 15))
    
    # Read from standard input
    try:
        index = int(input("Enter an index: "))
        result = get_value_from_array(id_sequence, size, index)
        sys.exit(result if result >= 0 else 1)
    except ValueError:
        sys.exit(1)
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
