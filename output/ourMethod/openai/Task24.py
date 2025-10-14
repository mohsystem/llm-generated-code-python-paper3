from typing import List

def is_valid_pin(pin: str) -> bool:
    if not isinstance(pin, str):
        return False
    n = len(pin)
    if n not in (4, 6):
        return False
    for ch in pin:
        if ch < '0' or ch > '9':
            return False
    return True

if __name__ == "__main__":
    tests: List[str] = ["1234", "12345", "a234", "0000", "098765"]
    for t in tests:
        print(f"{t} -> {is_valid_pin(t)}")