
def get_vehicle(vehicles, index):
    if 0 <= index < len(vehicles):
        return vehicles[index]
    return "Invalid index"

def print_all_vehicles(vehicles):
    for vehicle in vehicles:
        print(vehicle)

if __name__ == "__main__":
    vehicles = ["Car", "Truck", "Motorcycle", "Bus", "Bicycle"]
    
    # Test case 1: Valid index 0
    print("Test 1 - Index 0:", get_vehicle(vehicles, 0))
    
    # Test case 2: Valid index 2
    print("Test 2 - Index 2:", get_vehicle(vehicles, 2))
    
    # Test case 3: Valid index 4
    print("Test 3 - Index 4:", get_vehicle(vehicles, 4))
    
    # Test case 4: Invalid index -1
    print("Test 4 - Index -1:", get_vehicle(vehicles, -1))
    
    # Test case 5: Invalid index 10
    print("Test 5 - Index 10:", get_vehicle(vehicles, 10))
    
    print("\\nAll vehicles:")
    print_all_vehicles(vehicles)
