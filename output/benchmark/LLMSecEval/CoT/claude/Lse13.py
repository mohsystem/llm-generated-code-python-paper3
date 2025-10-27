
def get_value_at_index(index):
    id_sequence = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    
    # Input validation: check for negative index
    if not isinstance(index, int):
        print("Error: Index must be an integer")
        return None
    
    if index < 0:
        print("Error: Index cannot be negative")
        return None
    
    # Boundary check: ensure index is within array bounds
    if index >= len(id_sequence):
        print("Error: Index out of bounds")
        return None
    
    return id_sequence[index]


def test_case(index, description):
    print(f"\\nTest: {description}")
    result = get_value_at_index(index)
    if result is not None:
        print(f"Result: {result}")


def main():
    # Test cases
    print("=== Running Test Cases ===")
    test_case(0, "Valid index 0")
    test_case(5, "Valid index 5")
    test_case(9, "Valid index at boundary")
    test_case(-1, "Invalid negative index")
    test_case(15, "Invalid index out of bounds")
    
    # Interactive mode
    print("\\n=== Interactive Mode ===")
    try:
        user_input = input("Enter an index value: ")
        index = int(user_input)
        result = get_value_at_index(index)
        if result is not None:
            print(f"Value at index {index}: {result}")
    except ValueError:
        print("Error: Invalid input. Please enter an integer.")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
