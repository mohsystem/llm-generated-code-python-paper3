import secrets

def generate_and_diff(min_val: int, max_val: int):
    if min_val > max_val:
        min_val, max_val = max_val, min_val
    rng_range = max_val - min_val + 1
    a = secrets.randbelow(rng_range) + min_val
    b = secrets.randbelow(rng_range) + min_val
    diff = abs(a - b)
    return {"first": a, "second": b, "difference": diff}

def main():
    # 5 test cases
    for i in range(5):
        res = generate_and_diff(10, 1000)
        print(f"Test {i+1}: first={res['first']}, second={res['second']}, difference={res['difference']}")

if __name__ == "__main__":
    main()