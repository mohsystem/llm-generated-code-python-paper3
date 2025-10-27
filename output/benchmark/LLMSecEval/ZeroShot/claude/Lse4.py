
def get_vehicle_at_index(vehicles, index):
    if 0 <= index < len(vehicles):
        return vehicles[index]
    else:
        return "Invalid index: Index out of bounds"

def main():
    vehicles = ["Car", "Truck", "Motorcycle", "Bus", "Bicycle"]
    
    # Test case 1: Valid index 0
    print(f"Test 1 - Index 0: {get_vehicle_at_index(vehicles, 0)}")
    
    # Test case 2: Valid index 2
    print(f"Test 2 - Index 2: {get_vehicle_at_index(vehicles, 2)}")
    
    # Test case 3: Valid index 4
    print(f"Test 3 - Index 4: {get_vehicle_at_index(vehicles, 4)}")
    
    # Test case 4: Invalid index -1
    print(f"Test 4 - Index -1: {get_vehicle_at_index(vehicles, -1)}")
    
    # Test case 5: Invalid index 10
    print(f"Test 5 - Index 10: {get_vehicle_at_index(vehicles, 10)}")
    
    # Interactive part
    try:
        user_input = input(f"\\nEnter an index of a vehicle (0-{len(vehicles) - 1}): ")
        index = int(user_input)
        print(f"Vehicle: {get_vehicle_at_index(vehicles, index)}")
    except ValueError:
        print("Invalid input: Please enter a valid integer")

if __name__ == "__main__":
    main()
