import random

def generate_random_number():
    """
    Generates a random integer greater than 1000.
    
    Returns:
        int: A random integer in the range [1001, 2147483647].
    """
    # We need a number strictly greater than 1000, so the minimum is 1001.
    # The random.randint(a, b) function returns a random integer N such that a <= N <= b.
    # Python's integers support arbitrary precision, so overflow is not a concern,
    # but we choose a reasonable upper bound for practicality, such as the maximum
    # value for a 32-bit signed integer.
    lower_bound = 1001
    upper_bound = 2**31 - 1
    
    # For cryptographically secure random numbers, random.SystemRandom().randint() could be used.
    return random.randint(lower_bound, upper_bound)

if __name__ == "__main__":
    print("Generating 5 random numbers greater than 1000:")
    for i in range(5):
        # Using an f-string for formatted output.
        print(f"Test Case {i + 1}: {generate_random_number()}")