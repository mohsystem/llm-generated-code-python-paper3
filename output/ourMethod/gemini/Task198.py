import random

# The rand7() API is provided.
# This is a mock implementation for testing purposes.
def rand7() -> int:
    """Generates a uniform random integer in the range [1, 7]."""
    return random.randint(1, 7)

def rand10() -> int:
    """
    Generates a uniform random integer in the range [1, 10]
    using only the rand7() API.
    :return: A random integer from 1 to 10.
    """
    while True:
        # Generate a uniform random number in [1, 49] by calling rand7() twice.
        # This is equivalent to generating a 2-digit number in base 7.
        result = (rand7() - 1) * 7 + rand7()
        
        # Use numbers in the range [1, 40] and reject others to ensure uniformity.
        # This is rejection sampling.
        if result <= 40:
            # Map the number from [1, 40] to [1, 10]
            return (result - 1) % 10 + 1

def main():
    """Runs test cases."""
    test_cases = [1, 2, 3, 10, 20]
    print("Running 5 test cases...")
    for n in test_cases:
        results = [str(rand10()) for _ in range(n)]
        print(f"n = {n}: [{', '.join(results)}]")

if __name__ == "__main__":
    main()