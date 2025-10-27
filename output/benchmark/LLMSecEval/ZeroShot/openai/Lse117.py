import secrets

def a(value: float) -> str:
    return str(value)

def _secure_random_float() -> float:
    # Generate a float in [0.0, 1.0) using 53 random bits for double precision
    return secrets.randbits(53) / (1 << 53)

def generate_random_float_strings():
    fa = _secure_random_float()
    fb = _secure_random_float()
    fc = _secure_random_float()

    str_a = a(fa)
    str_b = a(fb)
    str_c = a(fc)

    return [str_a, str_b, str_c]

def main():
    for _ in range(5):
        res = generate_random_float_strings()
        print(res[0], res[1], res[2])

if __name__ == "__main__":
    main()