import random
import sys

def generate_random_number_greater_than_1000():
    """
    Generates a cryptographically secure random number greater than 1000.
    
    This function uses random.SystemRandom, which utilizes os.urandom() 
    on platforms that support it, providing access to cryptographically
    secure pseudo-random number generators (CSPRNG) from the OS.
    
    Returns:
        int: A random integer greater than 1000.
    """
    try:
        # Create a generator that uses a secure source of randomness.
        secure_generator = random.SystemRandom()
        
        # Define the range. We need a number > 1000, so the range starts at 1001.
        # sys.maxsize is a common upper bound, but for consistency with 32-bit integers,
        # we can use a value like 2**31 - 1.
        lower_bound = 1001
        upper_bound = 2**31 - 1
        
        # randint is inclusive of both endpoints.
        return secure_generator.randint(lower_bound, upper_bound)
    except NotImplementedError:
        # This occurs if os.urandom() is not available.
        # Handle the error gracefully.
        print("Error: Secure random number source (os.urandom) not available on this system.", file=sys.stderr)
        return -1 # Or raise an exception

if __name__ == "__main__":
    print("Generating 5 random numbers greater than 1000:")
    for i in range(5):
        random_num = generate_random_number_greater_than_1000()
        if random_num != -1:
            print(f"Test Case {i + 1}: {random_num}")