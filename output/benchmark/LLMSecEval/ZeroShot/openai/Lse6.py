from typing import List, Optional
import os
import sys

def get_vehicle(vehicles: List[str], index: int) -> Optional[str]:
    if vehicles is None:
        return None
    if not isinstance(index, int):
        return None
    if index < 0 or index >= len(vehicles):
        return None
    return vehicles[index]

def print_vehicles(vehicles: List[str]) -> None:
    if vehicles is None:
        return
    for i, v in enumerate(vehicles):
        print(f"Vehicle[{i}]: {v}")

def main() -> None:
    vehicles = ["Car", "Bike", "Truck", "Boat", "Plane"]

    # Optional interactive prompt controlled by environment variable
    if os.getenv("RUN_INTERACTIVE"):
        try:
            line = input("Enter vehicle index: ").strip()
            idx = int(line)
            result = get_vehicle(vehicles, idx)
            if result is not None:
                print(f"Selected vehicle: {result}")
            else:
                print("Invalid index.")
        except Exception:
            print("Invalid input. Please enter an integer index.")
    else:
        print("RUN_INTERACTIVE not set; skipping interactive prompt.")

    # 5 test cases
    test_indices = [0, 4, 2, -1, 10]
    for idx in test_indices:
        result = get_vehicle(vehicles, idx)
        print(f"Test index {idx}: {result if result is not None else 'Invalid index'}")

    # Loop and print all vehicles
    print_vehicles(vehicles)

if __name__ == "__main__":
    main()