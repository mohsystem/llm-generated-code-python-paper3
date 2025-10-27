VEHICLES = ["Car", "Bus", "Truck", "Bike", "Scooter", "Van", "SUV"]

def get_vehicle_at_index(index_input: str) -> str:
    if index_input is None:
        return "Error: index input is null"
    s = index_input.strip()
    if not s:
        return "Error: empty index input"
    try:
        idx = int(s)
    except ValueError:
        return "Error: invalid index format"
    if idx < 0 or idx >= len(VEHICLES):
        return "Error: index out of bounds"
    return VEHICLES[idx]

if __name__ == "__main__":
    tests = ["0", "2", "6", "-1", "abc"]
    for t in tests:
        print(f'Input: "{t}" -> {get_vehicle_at_index(t)}')