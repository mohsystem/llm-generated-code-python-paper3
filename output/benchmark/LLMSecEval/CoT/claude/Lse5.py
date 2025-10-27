
def print_element_at_index(array, index_str):
    if not index_str or not index_str.strip():
        print("Error: Index argument is empty or null")
        return
    
    try:
        index = int(index_str.strip())
        
        if index < 0 or index >= len(array):
            print(f"Error: Index {index} is out of bounds. Valid range: 0-{len(array) - 1}")
            return
        
        print(f"Element at index {index}: {array[index]}")
    except ValueError:
        print(f"Error: Invalid integer format: {index_str}")

if __name__ == "__main__":
    elements = ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape"]
    
    # Test cases
    print("Test Case 1: Valid index 0")
    print_element_at_index(elements, "0")
    
    print("\\nTest Case 2: Valid index 3")
    print_element_at_index(elements, "3")
    
    print("\\nTest Case 3: Negative index")
    print_element_at_index(elements, "-1")
    
    print("\\nTest Case 4: Out of bounds index")
    print_element_at_index(elements, "10")
    
    print("\\nTest Case 5: Invalid format")
    print_element_at_index(elements, "abc")
