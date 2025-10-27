from typing import List

VEHICLES: List[str] = ["Car", "Truck", "Bike", "Bus", "Van"]

def get_vehicle_by_index(index_input: str) -> str:
    if index_input is None:
        return "Invalid input: null"
    s = index_input.strip()
    if not s:
        return "Invalid input: empty"
    # Validate integer format
    if not (s.lstrip("+-").isdigit()):
        return "Invalid input: not an integer"
    try:
        idx = int(s, 10)
    except Exception:
        return "Invalid input: not an integer"
    if idx < 0:
        return "Invalid index: must be between 0 and {}".format(len(VEHICLES) - 1)
    if idx >= len(VEHICLES):
        return "Invalid index: must be between 0 and {}".format(len(VEHICLES) - 1)
    return VEHICLES[idx]

if __name__ == "__main__":
    tests = ["2", " 0 ", "-1", "10", "abc"]
    for t in tests:
        result = get_vehicle_by_index(t)
        print(f"Input: '{t}' => {result}")