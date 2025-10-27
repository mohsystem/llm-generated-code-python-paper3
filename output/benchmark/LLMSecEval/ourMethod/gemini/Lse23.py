import secrets

def generate_and_print_random_sum():
    """
    Generates three random integers > 1000 using a secure generator, 
    calculates their sum, and prints the results.
    """
    # Generate three random integers larger than 1000.
    # We'll generate numbers in the range [1001, 9999].
    # The size of the range is 9999 - 1001 + 1 = 8999.
    # secrets.randbelow(n) returns a random int in [0, n-1].
    # To get a number in [1001, 9999], we use secrets.randbelow(8999) + 1001.
    a = secrets.randbelow(8999) + 1001
    b = secrets.randbelow(8999) + 1001
    c = secrets.randbelow(8999) + 1001
    
    # Add the three integers. Python integers handle arbitrary size, so no overflow.
    total_sum = a + b + c
    
    # Print the results in the specified format using an f-string.
    print(f"a : {a} b : {b} c : {c} sum: {total_sum} sum2: {total_sum}")

def main():
    """
    Main function to run 5 test cases.
    """
    for _ in range(5):
        generate_and_print_random_sum()

if __name__ == "__main__":
    main()