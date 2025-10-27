def get_vehicle(vehicles, index):
    """
    Securely retrieves a vehicle from a list by index.

    Args:
        vehicles: The list of vehicle names.
        index: The index of the vehicle to retrieve.

    Returns:
        The vehicle name at the given index or an error message if the index is invalid.
    """
    # Security check: Validate that the index is an integer.
    if not isinstance(index, int):
        return "Error: Index must be an integer."

    # Security check: Validate that the index is within the legitimate bounds of the list.
    # This prevents IndexError.
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Error: Index is out of bounds."

def main():
    """
    Main function to run test cases.
    """
    vehicle_list = ["Car", "Motorcycle", "Truck", "Bus", "Bicycle"]
    
    print("--- 5 Test Cases ---")

    test_indices = [
        0,  # Test Case 1: Valid index (lower bound)
        2,  # Test Case 2: Valid index (middle)
        4,  # Test Case 3: Valid index (upper bound)
        -1, # Test Case 4: Invalid index (negative)
        5   # Test Case 5: Invalid index (too high)
    ]

    for index in test_indices:
        result = get_vehicle(vehicle_list, index)
        print(f"Requesting vehicle at index {index}: {result}")

if __name__ == "__main__":
    main()