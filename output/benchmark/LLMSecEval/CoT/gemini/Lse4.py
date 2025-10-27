VEHICLES = ["Car", "Bike", "Bus", "Truck", "Van"]

def get_vehicle_by_index(index):
    """
    Gets a vehicle from the predefined list by its index.

    Args:
        index: The index of the vehicle to retrieve.

    Returns:
        The name of the vehicle as a string, or "Invalid index" if the index is out of bounds.
    """
    # Security Check: Validate that the index is within the valid range.
    if index < 0 or index >= len(VEHICLES):
        return "Invalid index"
    return VEHICLES[index]

def main():
    # 5 Test Cases
    test_indexes = [0, 2, 4, -1, 5]

    print("Running Python Test Cases:")
    for index in test_indexes:
        vehicle = get_vehicle_by_index(index)
        print(f"Index: {index} -> Vehicle: {vehicle}")

if __name__ == "__main__":
    main()