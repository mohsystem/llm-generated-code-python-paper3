
def get_vehicle_at_index(vehicles, index):
    """\n    Safely retrieve a vehicle at the specified index with bounds checking.\n    """
    # Input validation
    if vehicles is None or len(vehicles) == 0:
        return "Error: Vehicle list is empty or None"
    
    # Bounds checking
    if not isinstance(index, int):
        return "Error: Index must be an integer"
    
    if index < 0 or index >= len(vehicles):
        return f"Error: Index out of bounds. Valid range: 0-{len(vehicles) - 1}"
    
    return vehicles[index]

def print_all_vehicles(vehicles):
    """\n    Print all vehicles in the array with their indices.\n    """
    if vehicles is None or len(vehicles) == 0:
        print("No vehicles to display.")
        return
    
    print("\\nAll vehicles:")
    for i in range(len(vehicles)):
        print(f"Index {i}: {vehicles[i]}")

def main():
    vehicles = ["Car", "Truck", "Motorcycle", "Bus", "Bicycle"]
    
    # Test cases
    print("=== Test Case 1: Valid index 0 ===")
    print(f"Vehicle at index 0: {get_vehicle_at_index(vehicles, 0)}")
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 2: Valid index 3 ===")
    print(f"Vehicle at index 3: {get_vehicle_at_index(vehicles, 3)}")
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 3: Invalid negative index ===")
    print(f"Vehicle at index -1: {get_vehicle_at_index(vehicles, -1)}")
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 4: Invalid index too large ===")
    print(f"Vehicle at index 10: {get_vehicle_at_index(vehicles, 10)}")
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 5: Last valid index ===")
    print(f"Vehicle at index 4: {get_vehicle_at_index(vehicles, 4)}")
    print_all_vehicles(vehicles)

if __name__ == "__main__":
    main()
