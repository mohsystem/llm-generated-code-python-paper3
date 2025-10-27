import random

def a(value: float) -> str:
    return str(value)

def random_float() -> float:
    return random.random()

def main():
    # 5 test cases
    for i in range(1, 6):
        a_val = random_float()
        b_val = random_float()
        c_val = random_float()

        str_a = a(a_val)
        str_b = a(b_val)
        str_c = a(c_val)

        print(f"Test Case {i}:")
        print(f"str_a = {str_a}")
        print(f"str_b = {str_b}")
        print(f"str_c = {str_c}")
        print()

if __name__ == "__main__":
    main()