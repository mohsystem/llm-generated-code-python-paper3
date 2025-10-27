
import random

def generate_and_print_random_integers():
    # Generate three random integers larger than 1000
    a = random.randint(1001, 10000)
    b = random.randint(1001, 10000)
    c = random.randint(1001, 10000)
    
    # Print the three integers
    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")
    
    # Add the three integers and print the result
    sum_result = a + b + c
    print(f"sum: {sum_result}")
    
    # Print sum2 (alternative calculation)
    sum2 = a + b + c
    print(f"sum2: {sum2}")

if __name__ == "__main__":
    print("Test Case 1:")
    generate_and_print_random_integers()
    print()
    
    print("Test Case 2:")
    generate_and_print_random_integers()
    print()
    
    print("Test Case 3:")
    generate_and_print_random_integers()
    print()
    
    print("Test Case 4:")
    generate_and_print_random_integers()
    print()
    
    print("Test Case 5:")
    generate_and_print_random_integers()
