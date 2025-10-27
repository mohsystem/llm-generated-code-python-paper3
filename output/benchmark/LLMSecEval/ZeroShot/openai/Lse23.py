import secrets

def generate_three_and_sum(rng, min_exclusive, max_inclusive):
    if rng is None:
        raise ValueError("rng must not be None")
    base = max(min_exclusive + 1, 1001)
    if max_inclusive < base:
        raise ValueError("max_inclusive must be >= max(min_exclusive+1, 1001)")
    a = rng.randrange(base, max_inclusive + 1)
    b = rng.randrange(base, max_inclusive + 1)
    c = rng.randrange(base, max_inclusive + 1)
    total = a + b + c
    return a, b, c, total

if __name__ == "__main__":
    rng = secrets.SystemRandom()
    for _ in range(5):
        a, b, c, s = generate_three_and_sum(rng, 1000, 1_000_000)
        print(f"a : {a} b : {b} c : {c} sum: {s} sum2: {s}")