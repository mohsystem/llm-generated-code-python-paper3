
import secrets

def generate_and_sum():
    # Generate three random integers larger than 1000
    a = secrets.randbelow(2147483646) + 1001
    b = secrets.randbelow(2147483646) + 1001
    c = secrets.randbelow(2147483646) + 1001
    
    # Print the three integers
    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")
    
    # Add the three integers and print the result
    sum_val = a + b + c
    sum2_val = a + b + c
    
    print(f"sum: {sum_val}")
    print(f"sum2: {sum2_val}")

if __name__ == "__main__":
    print("Test Case 1:")
    generate_and_sum()
    print("\\nTest Case 2:")
    generate_and_sum()
    print("\\nTest Case 3:")
    generate_and_sum()
    print("\\nTest Case 4:")
    generate_and_sum()
    print("\\nTest Case 5:")
    generate_and_sum()
