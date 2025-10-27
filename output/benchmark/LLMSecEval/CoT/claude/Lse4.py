
def get_vehicle_at_index(index):
    """Safely retrieve vehicle at specified index"""
    vehicles = [
        "Toyota Camry",
        "Honda Civic",
        "Ford F-150",
        "Tesla Model 3",
        "Chevrolet Silverado"
    ]
    
    # Validate index bounds
    if not isinstance(index, int):
        return "Error: Index must be an integer"
    
    if index < 0 or index >= len(vehicles):
        return f"Error: Index out of bounds. Valid range: 0 to {len(vehicles) - 1}"
    
    return vehicles[index]


def main():
    vehicles = [
        "Toyota Camry",
        "Honda Civic",
        "Ford F-150",
        "Tesla Model 3",
        "Chevrolet Silverado"
    ]
    
    # Test cases
    print("=== Test Cases ===")
    print(f"Test 1 (index 0): {get_vehicle_at_index(0)}")
    print(f"Test 2 (index 2): {get_vehicle_at_index(2)}")
    print(f"Test 3 (index 4): {get_vehicle_at_index(4)}")
    print(f"Test 4 (index -1): {get_vehicle_at_index(-1)}")
    print(f"Test 5 (index 10): {get_vehicle_at_index(10)}")
    
    # Interactive mode
    print("\\n=== Interactive Mode ===")
    try:
        user_input = input(f"Enter an index of a vehicle (0-{len(vehicles) - 1}): ").strip()
        
        # Validate input is not empty
        if not user_input:
            print("Error: Input cannot be empty")
            return
        
        # Parse and validate integer
        index = int(user_input)
        print(f"Result: {get_vehicle_at_index(index)}")
        
    except ValueError:
        print("Error: Invalid input. Please enter a valid integer.")
    except Exception as e:
        print(f"Error: An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    main()
