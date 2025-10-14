import random

# This is the mock implementation of the provided API for testing purposes.
# The actual solution for rand10() does not use this directly.
def rand7():
    """
    @return a random integer in the range 1 to 7
    """
    return random.randint(1, 7)

def rand10():
    """
    Given the API rand7() that generates a uniform random integer in the range [1, 7],
    this function generates a uniform random integer in the range [1, 10].
    :rtype: int
    """
    while True:
        row = rand7()
        col = rand7()
        idx = (row - 1) * 7 + col  # Generates a uniform number in [1, 49]
        
        # Rejection sampling: reject values that would cause non-uniformity
        if idx <= 40:
            # Map the uniform range [1, 40] to [1, 10]
            return (idx - 1) % 10 + 1

def main():
    """ Main function with test cases """
    test_cases = [1, 2, 3, 5, 10]
    
    for i, n in enumerate(test_cases, 1):
        result = [rand10() for _ in range(n)]
        print(f"Test Case {i} (n={n}): {result}")

if __name__ == "__main__":
    main()