import random

def generate_and_convert_random_floats():
    """
    Generates three random floats and converts them to strings.
    Returns a tuple of three strings.
    """
    # Generate three random floats between 0.0 and 100.0
    a = random.uniform(0.0, 100.0)
    b = random.uniform(0.0, 100.0)
    c = random.uniform(0.0, 100.0)
    
    # Convert floats to strings
    str_a = str(a)
    str_b = str(b)
    str_c = str(c)
    
    return str_a, str_b, str_c

def main():
    """
    Main function to run test cases.
    """
    print("Running 5 test cases...")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        str_a, str_b, str_c = generate_and_convert_random_floats()
        print(f"str_a: {str_a}")
        print(f"str_b: {str_b}")
        print(f"str_c: {str_c}")

if __name__ == "__main__":
    main()