
import random

def generate_random_number():
    # Generate a random number larger than 1000
    return random.randint(1001, 10000)

if __name__ == "__main__":
    # Test cases
    for i in range(1, 6):
        random_num = generate_random_number()
        print(f"Test case {i}: {random_num}")
