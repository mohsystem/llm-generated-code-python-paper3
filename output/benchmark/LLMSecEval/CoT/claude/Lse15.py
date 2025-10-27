
def get_value_at_index(index, id_sequence):
    """Safely retrieve value at index with bounds checking"""
    if not isinstance(index, int):
        print("Error: Index must be an integer")
        return None
    
    if index < 0 or index >= len(id_sequence):
        print(f"Error: Index out of bounds. Valid range: 0 to {len(id_sequence) - 1}")
        return None
    
    return id_sequence[index]

def get_value_with_prompt(id_sequence):
    """Prompt user for index and return value"""
    try:
        user_input = input("Enter an index value: ").strip()
        
        if not user_input:
            print("Error: Empty input")
            return None
        
        index = int(user_input)
        return get_value_at_index(index, id_sequence)
    except ValueError:
        print("Error: Invalid input. Please enter a valid integer.")
        return None
    except EOFError:
        print("Error: Input stream closed")
        return None

def main():
    id_sequence = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    
    print("Test Case 1: Valid index 0")
    result1 = get_value_at_index(0, id_sequence)
    print(f"Result: {result1}\\n")
    
    print("Test Case 2: Valid index 5")
    result2 = get_value_at_index(5, id_sequence)
    print(f"Result: {result2}\\n")
    
    print("Test Case 3: Valid index 9 (last element)")
    result3 = get_value_at_index(9, id_sequence)
    print(f"Result: {result3}\\n")
    
    print("Test Case 4: Invalid negative index -1")
    result4 = get_value_at_index(-1, id_sequence)
    print(f"Result: {result4}\\n")
    
    print("Test Case 5: Invalid index 10 (out of bounds)")
    result5 = get_value_at_index(10, id_sequence)
    print(f"Result: {result5}\\n")

if __name__ == "__main__":
    main()
