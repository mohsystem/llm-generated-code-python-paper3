
import secrets

def generate_and_sum():
    # Generate three random integers larger than 1000
    a = secrets.randbelow(2147483647 - 1001) + 1001
    b = secrets.randbelow(2147483647 - 1001) + 1001
    c = secrets.randbelow(2147483647 - 1001) + 1001
    
    # Print the three integers
    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")
    
    # Add and print the result
    sum_val = a + b + c
    sum2 = a + b + c
    print(f"sum: {sum_val}")
    print(f"sum2: {sum2}")

if __name__ == "__main__":
    # Run 5 test cases
    for i in range(1, 6):
        print(f"Test case {i}:")
        generate_and_sum()
        print()
