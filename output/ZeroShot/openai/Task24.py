def validate_pin(s):
    if not isinstance(s, str):
        return False
    if len(s) not in (4, 6):
        return False
    return all('0' <= c <= '9' for c in s)

if __name__ == "__main__":
    tests = [
        "1234",
        "12345",
        "a234",
        "0000",
        "098765",
    ]
    for t in tests:
        print(f"{t} -> {validate_pin(t)}")