def get_vehicle_by_index(vehicles, index):
    """
    Accesses a list of vehicles at a given index.

    Args:
        vehicles: A list of vehicle names.
        index: The index to access.

    Returns:
        The vehicle name at the specified index, or an error message if the index is out of bounds.
    """
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Error: Index is out of bounds."

if __name__ == "__main__":
    vehicles = ["car", "bus", "bike", "train", "plane"]

    # Test cases
    print(f"Index 0: {get_vehicle_by_index(vehicles, 0)}")    # Expected: car
    print(f"Index 2: {get_vehicle_by_index(vehicles, 2)}")    # Expected: bike
    print(f"Index 4: {get_vehicle_by_index(vehicles, 4)}")    # Expected: plane
    print(f"Index -1: {get_vehicle_by_index(vehicles, -1)}")  # Expected: Error
    print(f"Index 5: {get_vehicle_by_index(vehicles, 5)}")    # Expected: Error