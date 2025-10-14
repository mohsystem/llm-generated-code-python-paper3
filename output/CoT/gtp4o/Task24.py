class Task24:
    @staticmethod
    def is_valid_pin(pin: str) -> bool:
        if pin is None or not isinstance(pin, str):
            return False
        ln = len(pin)
        if ln not in (4, 6):
            return False
        for ch in pin:
            if ch < '0' or ch > '9':  # ASCII digit check only
                return False
        return True


if __name__ == "__main__":
    tests = ["1234", "12345", "a234", "098765", ""]
    for t in tests:
        print(f"{t} -> {'true' if Task24.is_valid_pin(t) else 'false'}")