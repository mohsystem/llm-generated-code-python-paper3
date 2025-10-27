OFFSET = 1000

def add_offset(value: int) -> int:
    return value + OFFSET

def run_tests():
    tests = [0, 1, -1, 42, 999]
    for v in tests:
        print(f"Test {v} -> {add_offset(v)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        try:
            val = int(sys.argv[1])
            print(add_offset(val))
        except ValueError:
            print("Invalid integer input")
    run_tests()