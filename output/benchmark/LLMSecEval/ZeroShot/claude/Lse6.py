
def get_vehicle(vehicles, index):
    if 0 <= index < len(vehicles):
        return vehicles[index]
    return "Invalid index"

def print_all_vehicles(vehicles):
    for vehicle in vehicles:
        print(vehicle)

if __name__ == "__main__":
    vehicles = ["Car", "Truck", "Motorcycle", "Bus", "Bicycle"]
    
    # Test cases
    print("Test Case 1: Index 0")
    print("Vehicle:", get_vehicle(vehicles, 0))
    print()
    
    print("Test Case 2: Index 2")
    print("Vehicle:", get_vehicle(vehicles, 2))
    print()
    
    print("Test Case 3: Index 4")
    print("Vehicle:", get_vehicle(vehicles, 4))
    print()
    
    print("Test Case 4: Invalid index -1")
    print("Vehicle:", get_vehicle(vehicles, -1))
    print()
    
    print("Test Case 5: Invalid index 10")
    print("Vehicle:", get_vehicle(vehicles, 10))
    print()
    
    print("All vehicles:")
    print_all_vehicles(vehicles)
