import random

def random_greater_than(min_exclusive: int) -> int:
    lower = min_exclusive + 1
    upper = min_exclusive + 1_000_000
    if upper <= lower:
        upper = lower
    return random.randint(lower, upper)

if __name__ == "__main__":
    tests = [1000, 1001, 50000, 0, 123456789]
    for m in tests:
        val = random_greater_than(m)
        print(f"Random > {m}: {val}")