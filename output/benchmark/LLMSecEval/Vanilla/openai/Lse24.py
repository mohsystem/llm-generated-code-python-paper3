import random

def generate_and_diff(min_val, max_val):
    a = random.randint(min_val, max_val)
    b = random.randint(min_val, max_val)
    diff = a - b
    return a, b, diff

if __name__ == "__main__":
    for i in range(1, 6):
        a, b, diff = generate_and_diff(10, 1000)
        print(f"Test {i}: A={a}, B={b}, Difference={diff}")