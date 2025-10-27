from typing import List

VEHICLES: List[str] = [
    "Car", "Bike", "Truck", "Bus", "Scooter",
    "Van", "Train", "Boat", "Plane", "Tractor"
]

def get_vehicle_by_index(index_input: str) -> str:
    """
    Returns the vehicle at the given index as a string, or an error message.
    """
    if index_input is None:
        return "Invalid input"

    s = str(index_input).strip()
    if not s or len(s) > 20:
        return "Invalid input"

    # Validate numeric format
    if not __import__("re").fullmatch(r"[+-]?\d{1,10}", s):
        return "Invalid input"

    try:
        val = int(s, 10)
    except ValueError:
        return "Invalid input"

    if val < 0 or val >= len(VEHICLES):
        return "Index out of range"
    return VEHICLES[val]


if __name__ == "__main__":
    tests = ["0", "3", "10", "-1", "2"]
    for t in tests:
        print(f"Input: {t} -> Output: {get_vehicle_by_index(t)}")