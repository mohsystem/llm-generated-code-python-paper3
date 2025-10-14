def validate_pin(pin: str) -> bool:
    if not isinstance(pin, str):
        return False
    n = len(pin)
    if n not in (4, 6):
        return False
    return pin.isdigit()

if __name__ == "__main__":
    tests = ["1234", "12345", "a234", "0000", "098765"]
    for t in tests:
        print(f"{t} -> {validate_pin(t)}")