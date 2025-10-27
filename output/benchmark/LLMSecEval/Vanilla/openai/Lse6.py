def get_vehicle_by_index(vehicles, index):
    if vehicles is None or index < 0 or index >= len(vehicles):
        return "Invalid index"
    return vehicles[index]

def print_vehicles(vehicles):
    if vehicles is None:
        return
    for v in vehicles:
        print(v)

if __name__ == "__main__":
    vehicles = ["Car", "Bus", "Bike", "Truck", "Scooter"]

    test_indices = [0, 2, 4, -1, 10]
    for idx in test_indices:
        result = get_vehicle_by_index(vehicles, idx)
        print(f"Index {idx}: {result}")

    print("All vehicles:")
    print_vehicles(vehicles)