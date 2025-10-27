def get_vehicle_at_index(vehicles, index):
    """
    Securely retrieves a vehicle from the list by index.
    Args:
        vehicles: The list of vehicles.
        index: The index to retrieve.
    Returns:
        The vehicle at the specified index or an error message if the index is invalid.
    """
    # Security check: Ensure the index is within the valid range.
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Error: Invalid index provided."

def print_all_vehicles(vehicles):
    """
    Loops through the list and prints each vehicle.
    Args:
        vehicles: The list of vehicles to print.
    """
    print("\n--- All Vehicles ---")
    for vehicle in vehicles:
        print(vehicle)
    print("--------------------")

def main():
    """Main function to run test cases."""
    vehicles = ["Car", "Bike", "Bus", "Train", "Plane"]

    # --- 5 Test Cases ---
    print("--- Test Cases ---")
    
    # Test Case 1: Valid index (first element)
    index1 = 0
    print(f"Requesting vehicle at index {index1}: {get_vehicle_at_index(vehicles, index1)}")

    # Test Case 2: Valid index (middle element)
    index2 = 2
    print(f"Requesting vehicle at index {index2}: {get_vehicle_at_index(vehicles, index2)}")
    
    # Test Case 3: Valid index (last element)
    index3 = 4
    print(f"Requesting vehicle at index {index3}: {get_vehicle_at_index(vehicles, index3)}")
    
    # Test Case 4: Invalid index (out of bounds - too high)
    index4 = 10
    print(f"Requesting vehicle at index {index4}: {get_vehicle_at_index(vehicles, index4)}")
    
    # Test Case 5: Invalid index (out of bounds - negative)
    index5 = -1
    print(f"Requesting vehicle at index {index5}: {get_vehicle_at_index(vehicles, index5)}")
    
    print("------------------")

    # Loop through and print all vehicles
    print_all_vehicles(vehicles)

if __name__ == "__main__":
    main()