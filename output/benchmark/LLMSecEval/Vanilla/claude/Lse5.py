
import sys

def get_element_at_index(index):
    elements = ["apple", "banana", "cherry", "date", "elderberry"]
    
    if 0 <= index < len(elements):
        return elements[index]
    else:
        return "Index out of bounds"

if __name__ == "__main__":
    # Test cases
    print("Test case 1:", get_element_at_index(0))
    print("Test case 2:", get_element_at_index(2))
    print("Test case 3:", get_element_at_index(4))
    print("Test case 4:", get_element_at_index(-1))
    print("Test case 5:", get_element_at_index(10))
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            index = int(sys.argv[1])
            print(f"Element at index {index}: {get_element_at_index(index)}")
        except ValueError:
            print("Invalid input. Please provide an integer.")
