import random

def a(x: float) -> str:
    return str(x)

def run_test_case(rng: random.Random):
    fa = rng.random()
    fb = rng.random()
    fc = rng.random()

    str_a = a(fa)
    str_b = a(fb)
    str_c = a(fc)

    print(f"str_a={str_a}, str_b={str_b}, str_c={str_c}")
    return str_a, str_b, str_c

if __name__ == "__main__":
    rng = random.Random()
    for _ in range(5):
        run_test_case(rng)