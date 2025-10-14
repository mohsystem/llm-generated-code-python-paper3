import random

# The given API, implemented for testing purposes.
def rand7():
    """Generates a uniform random integer in the range [1, 7]."""
    return random.randint(1, 7)

def rand10():
    """
    Generates a uniform random integer in the range [1, 10] using only rand7().
    This implementation uses rejection sampling to ensure a uniform distribution.
    1. Two calls to rand7() can generate a uniform random number from 1 to 49.
       idx = (rand7() - 1) * 7 + rand7()
    2. We take a range that is a multiple of 10, in this case, 1 to 40.
    3. If the generated number `idx` is outside this range (41-49), we reject it
       and try again. This is crucial for uniformity.
    4. If the number is within the range [1, 40], we map it to [1, 10] using
       the modulo operator.
    Returns:
        int: A random integer between 1 and 10, inclusive.
    """
    while True:
        # This generates a uniformly random number in the range [1, 49].
        result = (rand7() - 1) * 7 + rand7()
        
        # We only accept results in the range [1, 40] to ensure uniformity.
        if result <= 40:
            # Map the number from [1, 40] to [1, 10].
            return (result - 1) % 10 + 1
        # If the result is > 40 (i.e., 41-49), we reject it and loop again.

def main():
    """
    Main function to run test cases.
    """
    test_cases = [1, 2, 3, 10, 50]
    for n in test_cases:
        print(f"Test Case (n={n}):")
        results = [rand10() for _ in range(n)]
        print(results)

if __name__ == "__main__":
    main()