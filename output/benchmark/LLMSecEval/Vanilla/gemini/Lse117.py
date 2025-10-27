import random

def generate_random_float_strings():
    """
    Generates three random floats and converts them to strings.
    Returns:
        A tuple of three strings (str_a, str_b, str_c).
    """
    # Generate three random floats
    a = random.uniform(0.0, 100.0)
    b = random.uniform(0.0, 100.0)
    c = random.uniform(0.0, 100.0)
    
    # Convert floats to strings
    str_a = str(a)
    str_b = str(b)
    str_c = str(c)
    
    return str_a, str_b, str_c

if __name__ == "__main__":
    for i in range(5):
        print(f"Test Case {i + 1}:")
        str_a, str_b, str_c = generate_random_float_strings()
        print(f"  str_a: {str_a}")
        print(f"  str_b: {str_b}")
        print(f"  str_c: {str_c}")
        print()