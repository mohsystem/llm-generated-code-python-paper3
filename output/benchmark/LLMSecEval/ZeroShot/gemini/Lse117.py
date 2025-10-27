import random

def generate_and_convert_random_floats():
    """
    Generates three cryptographically secure random floats and converts them to strings.
    Uses random.SystemRandom, which relies on os.urandom() for high-quality randomness.
    
    Returns:
        tuple: A tuple containing three strings (str_a, str_b, str_c).
    """
    # For security-sensitive applications, use random.SystemRandom which uses the
    # most secure source of randomness provided by the OS (e.g., os.urandom).
    secure_random = random.SystemRandom()

    # Generate three random floats. secure_random.random() returns a float in the range [0.0, 1.0).
    a = secure_random.random()
    b = secure_random.random()
    c = secure_random.random()

    # Convert floats to strings using the built-in str() function.
    str_a = str(a)
    str_b = str(b)
    str_c = str(c)

    return str_a, str_b, str_c

if __name__ == "__main__":
    # Run 5 test cases to demonstrate the functionality.
    for i in range(5):
        print(f"Test Case {i + 1}:")
        
        # The resulting strings are stored in these variables as per the prompt.
        str_a, str_b, str_c = generate_and_convert_random_floats()
        
        print(f"  str_a: {str_a}")
        print(f"  str_b: {str_b}")
        print(f"  str_c: {str_c}")
        print()