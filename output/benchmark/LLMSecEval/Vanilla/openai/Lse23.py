import random

def run_case(seed: int) -> int:
    rnd = random.Random(seed)
    a = rnd.randint(1001, 10000)
    b = rnd.randint(1001, 10000)
    c = rnd.randint(1001, 10000)
    s = a + b + c
    print(f"a : {a} b : {b} c : {c}")
    print(f"sum: {s} sum2: {s}")
    return s

if __name__ == "__main__":
    for seed in [1, 2, 3, 4, 5]:
        run_case(seed)