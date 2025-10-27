
import sys

def get_element_at_index(index):
    elements = ["apple", "banana", "cherry", "date", "elderberry"]
    
    if index < 0 or index >= len(elements):
        return "Error: Index out of bounds"
    
    return elements[index]

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:", get_element_at_index(0))
    print("Test Case 2:", get_element_at_index(2))
    print("Test Case 3:", get_element_at_index(4))
    print("Test Case 4:", get_element_at_index(-1))
    print("Test Case 5:", get_element_at_index(10))
    
    # Command line argument processing
    if len(sys.argv) > 1:
        try:
            index = int(sys.argv[1])
            print("\\nCommand line result:", get_element_at_index(index))
        except ValueError:
            print("Error: Invalid number format")
