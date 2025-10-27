def get_vehicle(vehicles, index):
    """
    Retrieves a vehicle from the list at a specified index.
    Includes bounds checking to prevent errors.

    Args:
        vehicles: The list of vehicle strings.
        index: The index of the vehicle to retrieve.

    Returns:
        The vehicle string at the given index, or an error message if the index is invalid.
    """
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return f"Error: Index {index} is out of bounds."

def print_all_vehicles(vehicles):
    """
    Loops through the list and prints each vehicle.

    Args:
        vehicles: The list of vehicle strings to print.
    """
    print("\n--- All Vehicles ---")
    for vehicle in vehicles:
        print(vehicle)
    print("--------------------")

def main():
    """Main function to run the program and test cases."""
    vehicles = ["Car", "Bike", "Bus", "Train", "Plane"]

    # Print all vehicles
    print_all_vehicles(vehicles)

    # 5 Test Cases
    print("\n--- Test Cases ---")
    test_indices = [1, 3, 0, -1, 5]

    for i, index in enumerate(test_indices):
        print(f"Test Case {i + 1}: Getting vehicle at index {index}")
        vehicle = get_vehicle(vehicles, index)
        print(f"Result: {vehicle}")

if __name__ == "__main__":
    main()