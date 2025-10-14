
import random
import string
import secrets

def generate_random_int(min_val, max_val):
    """Generate random integer between min and max (inclusive)"""
    return random.randint(min_val, max_val)

def generate_random_double():
    """Generate random double between 0.0 and 1.0"""
    return random.random()

def generate_random_token(length):
    """Generate random alphanumeric token of specified length"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_random_boolean():
    """Generate random boolean"""
    return random.choice([True, False])

def generate_random_int_array(size, min_val, max_val):
    """Generate array of random integers"""
    return [random.randint(min_val, max_val) for _ in range(size)]

if __name__ == "__main__":
    print("Test Case 1: Random integer between 1 and 100")
    print(generate_random_int(1, 100))
    
    print("\\nTest Case 2: Random double")
    print(generate_random_double())
    
    print("\\nTest Case 3: Random token of length 16")
    print(generate_random_token(16))
    
    print("\\nTest Case 4: Random boolean")
    print(generate_random_boolean())
    
    print("\\nTest Case 5: Array of 5 random integers between 10 and 50")
    random_array = generate_random_int_array(5, 10, 50)
    print(random_array)
