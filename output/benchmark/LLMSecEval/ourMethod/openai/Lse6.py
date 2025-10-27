from typing import Optional, List

def get_vehicle(vehicles: List[str], index: int) -> Optional[str]:
    if vehicles is None:
        return None
    if 0 <= index < len(vehicles):
        return vehicles[index]
    return None

def main() -> None:
    vehicles: List[str] = ["Car", "Bike", "Truck", "Bus", "Scooter"]

    # Prompt the user for the index and return that vehicle
    print(f"Available vehicles count: {len(vehicles)}")
    try:
        raw = input(f"Enter an index (0 to {len(vehicles) - 1}): ")
    except Exception:
        raw = ""
    s = (raw or "").strip()
    if len(s) > 20:
        print("Invalid index.")
    else:
        try:
            idx = int(s)
            chosen = get_vehicle(vehicles, idx)
            if chosen is not None:
                print(f"Selected vehicle: {chosen}")
            else:
                print("Invalid index.")
        except ValueError:
            print("Invalid index.")

    # Loop through the array and print out each vehicle
    print("All vehicles:")
    for i, v in enumerate(vehicles):
        print(f"{i}: {v}")

    # 5 test cases
    print("Test cases:")
    test_indices = [0, 2, 4, -1, 10]
    for idx in test_indices:
        result = get_vehicle(vehicles, idx)
        if result is not None:
            print(f"Index {idx} -> {result}")
        else:
            print(f"Index {idx} -> Invalid index.")

if __name__ == "__main__":
    main()