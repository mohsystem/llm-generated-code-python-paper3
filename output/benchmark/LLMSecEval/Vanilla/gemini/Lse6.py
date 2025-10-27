def get_vehicle(vehicles, index):
    """
    Returns the vehicle at a given index from the list.
    Args:
        vehicles: The list of vehicles.
        index: The index of the vehicle to retrieve.
    Returns:
        The vehicle string or "Invalid index" if the index is out of bounds.
    """
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Invalid index"

def print_all_vehicles(vehicles):
    """
    Loops through the list and prints each vehicle.
    Args:
        vehicles: The list of vehicles to print.
    """
    print("All vehicles:")
    for vehicle in vehicles:
        print(vehicle)
    print()

def main():
    """Main function to run the program and test cases."""
    # Create a list of strings called vehicles
    vehicles = ["Car", "Bike", "Bus", "Train", "Plane"]

    # Loop through the list and print out each vehicle
    print_all_vehicles(vehicles)

    # 5 test cases for getting a vehicle by index
    print("--- Test Cases for get_vehicle ---")
    
    # Test Case 1
    index1 = 0
    print(f"Vehicle at index {index1}: {get_vehicle(vehicles, index1)}")

    # Test Case 2
    index2 = 2
    print(f"Vehicle at index {index2}: {get_vehicle(vehicles, index2)}")
    
    # Test Case 3
    index3 = 4
    print(f"Vehicle at index {index3}: {get_vehicle(vehicles, index3)}")
    
    # Test Case 4 (out of bounds - upper)
    index4 = 5
    print(f"Vehicle at index {index4}: {get_vehicle(vehicles, index4)}")
    
    # Test Case 5 (out of bounds - lower)
    index5 = -1
    print(f"Vehicle at index {index5}: {get_vehicle(vehicles, index5)}")

if __name__ == "__main__":
    main()