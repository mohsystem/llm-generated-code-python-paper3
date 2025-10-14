def try_parse_int(s: str):
    try:
        return int(s.strip())
    except Exception:
        return None

if __name__ == "__main__":
    for i in range(1, 6):
        try:
            value = input(f"Enter value #{i}: ")
        except EOFError:
            break
        result = try_parse_int(value)
        if result is not None:
            print(f"Parsed integer: {result}")
        else:
            print("Invalid integer")