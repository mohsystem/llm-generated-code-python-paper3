import secrets

def generate_and_print_sum():
    """
    Generates three cryptographically secure random integers greater than 1000,
    prints them, calculates their sum, and prints the sum.
    """
    # Use the 'secrets' module for generating cryptographically strong random numbers.
    # This is preferred over the 'random' module for security-sensitive applications.
    
    # Generate three integers in the range [1001, 30000].
    # secrets.randbelow(29000) -> [0, 28999]
    # secrets.randbelow(29000) + 1001 -> [1001, 30000]
    a = secrets.randbelow(29000) + 1001
    b = secrets.randbelow(29000) + 1001
    c = secrets.randbelow(29000) + 1001

    # Python's integers have arbitrary precision, so integer overflow is not a concern.
    sum_val = a + b + c

    # Print the numbers and their sum in the specified format.
    print(f"a : {a} b : {b} c : {c} sum: {sum_val} sum2: {sum_val}")

def main():
    """ Main function to run test cases. """
    print("Python execution:")
    # Run 5 test cases as requested.
    for _ in range(5):
        generate_and_print_sum()

if __name__ == "__main__":
    main()