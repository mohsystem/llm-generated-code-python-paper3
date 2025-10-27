import random

def generate_and_print_random_sum():
    """
    Generates three random integers larger than 1000, calculates their sum,
    and prints the results in a specific format.
    """
    # random.randint(a, b) returns a random integer N such that a <= N <= b.
    # We choose the range [1001, 9999] to get numbers larger than 1000.
    a = random.randint(1001, 9999)
    b = random.randint(1001, 9999)
    c = random.randint(1001, 9999)

    # Calculate the sum. Python integers handle arbitrary size, so no overflow risk.
    total_sum = a + b + c

    # Print the result using an f-string for clear and safe formatting.
    print(f"a : {a} b : {b} c : {c} sum: {total_sum} sum2: {total_sum}")

def main():
    # Run 5 test cases as requested.
    print("Running Python Test Cases:")
    for _ in range(5):
        generate_and_print_random_sum()

if __name__ == "__main__":
    main()