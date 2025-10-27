import typing

def get_vehicle(vehicles: typing.List[str], index: int) -> str:
    """
    Retrieves a vehicle from the list at the specified index.

    Args:
        vehicles: The list of vehicles.
        index: The index of the vehicle to retrieve.

    Returns:
        The vehicle string at the given index, or an error message if the index is invalid.
    """
    # Rule #1, #3, #4: Input validation - check if the index is within the valid bounds.
    if isinstance(index, int) and 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Error: Index out of bounds."

def print_all_vehicles(vehicles: typing.List[str]):
    """
    Prints all vehicles in the given list to the console.

    Args:
        vehicles: The list of vehicles to print.
    """
    print("All vehicles:")
    for vehicle in vehicles:
        print(vehicle)

def main():
    """
    Main function to demonstrate vehicle retrieval and listing.
    """
    # The list of strings called vehicles.
    vehicles = ["Car", "Bus", "Motorcycle", "Bicycle", "Truck"]

    # Loop through the list and print out each vehicle.
    print_all_vehicles(vehicles)
    print("--------------------")

    # 5 test cases
    print("Running test cases...")

    # Test Case 1: Valid index (0)
    test_index1 = 0
    print(f"Getting vehicle at index {test_index1}: {get_vehicle(vehicles, test_index1)}")

    # Test Case 2: Valid index (middle)
    test_index2 = 2
    print(f"Getting vehicle at index {test_index2}: {get_vehicle(vehicles, test_index2)}")

    # Test Case 3: Valid index (last element)
    test_index3 = 4
    print(f"Getting vehicle at index {test_index3}: {get_vehicle(vehicles, test_index3)}")

    # Test Case 4: Invalid index (negative)
    test_index4 = -1
    print(f"Getting vehicle at index {test_index4}: {get_vehicle(vehicles, test_index4)}")

    # Test Case 5: Invalid index (out of bounds)
    test_index5 = 5
    print(f"Getting vehicle at index {test_index5}: {get_vehicle(vehicles, test_index5)}")


if __name__ == "__main__":
    main()