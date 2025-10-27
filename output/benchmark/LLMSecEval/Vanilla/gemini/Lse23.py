import random

def generate_and_sum_randoms():
    a = random.randint(1001, 9999)
    b = random.randint(1001, 9999)
    c = random.randint(1001, 9999)

    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")

    total_sum = a + b + c
    print(f"sum: {total_sum}")
    print(f"sum2: {total_sum}")

if __name__ == "__main__":
    for i in range(5):
        generate_and_sum_randoms()
        if i < 4:
            print()