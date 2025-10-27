
def get_vehicle_at_index(vehicles, index):
    if 0 <= index < len(vehicles):
        return vehicles[index]
    return "Invalid index"

def main():
    vehicles = ["Car", "Bike", "Truck", "Bus", "Van", "Motorcycle"]
    
    # Test case 1
    print("Test 1:", get_vehicle_at_index(vehicles, 0))
    
    # Test case 2
    print("Test 2:", get_vehicle_at_index(vehicles, 3))
    
    # Test case 3
    print("Test 3:", get_vehicle_at_index(vehicles, 5))
    
    # Test case 4
    print("Test 4:", get_vehicle_at_index(vehicles, -1))
    
    # Test case 5
    print("Test 5:", get_vehicle_at_index(vehicles, 10))
    
    # Interactive mode
    index = int(input("\\nEnter an index of a vehicle: "))
    print(get_vehicle_at_index(vehicles, index))

if __name__ == "__main__":
    main()
