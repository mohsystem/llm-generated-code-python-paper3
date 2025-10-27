# Step 1: Problem understanding - Create vehicles array, prompt for index, return and print selected vehicle, loop print all.
# Step 2: Security requirements - Input validation, bounds checking.
# Step 3 & 5: Secure coding and final secure output.

from typing import List, Optional

def get_vehicle_at(vehicles: List[str], index: int) -> Optional[str]:
    if vehicles is None:
        return None
    if index < 0 or index >= len(vehicles):
        return None
    return vehicles[index]

def print_vehicles(vehicles: List[str]) -> None:
    if vehicles is None:
        return
    for i, v in enumerate(vehicles):
        print(f"vehicles[{i}] = {v}")

def main() -> None:
    vehicles = ["Car", "Bike", "Truck", "Bus", "Scooter"]
    try:
        raw = input(f"Enter vehicle index (0-{len(vehicles)-1}): ").strip()
        try:
            idx = int(raw)
        except ValueError:
            print("Invalid input. Please enter an integer.")
            idx = -1
        selected = get_vehicle_at(vehicles, idx)
        if selected is not None:
            print(f"Selected vehicle: {selected}")
        else:
            print("No vehicle found at the provided index.")
        print("All vehicles:")
        print_vehicles(vehicles)

        # 5 test cases
        print("\nTest cases:")
        test_indices = [0, 2, 4, -1, 10]
        for i, ti in enumerate(test_indices, 1):
            result = get_vehicle_at(vehicles, ti)
            print(f"Test {i} - index {ti}: {result if result is not None else 'Invalid index'}")
    except EOFError:
        # Handle no input scenarios gracefully
        print("No input provided.")

if __name__ == "__main__":
    main()