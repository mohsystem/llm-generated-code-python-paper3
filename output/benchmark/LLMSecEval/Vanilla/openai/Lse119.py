import random

def generate_random_float_strings(seed):
    rnd = random.Random(seed)
    f1 = rnd.random()
    f2 = rnd.random()
    f3 = rnd.random()

    string = "%.6f" % f1
    string2 = "%.6f" % f2
    string3 = "%.6f" % f3

    return [string, string2, string3]

def main():
    seeds = [1, 2, 3, 4, 5]
    for s in seeds:
        result = generate_random_float_strings(s)
        print(f"Seed {s}: {result}")

if __name__ == "__main__":
    main()