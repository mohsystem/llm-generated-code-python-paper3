
import secrets
import string

def generate_random_string(length):
    if length < 0:
        raise ValueError("Length must be non-negative")
    
    ascii_letters = string.ascii_letters
    return ''.join(secrets.choice(ascii_letters) for _ in range(length))

if __name__ == "__main__":
    # Test case 1: Generate string of length 10
    print(f"Test 1 (length 10): {generate_random_string(10)}")
    
    # Test case 2: Generate string of length 5
    print(f"Test 2 (length 5): {generate_random_string(5)}")
    
    # Test case 3: Generate string of length 20
    print(f"Test 3 (length 20): {generate_random_string(20)}")
    
    # Test case 4: Generate string of length 0
    print(f"Test 4 (length 0): '{generate_random_string(0)}'")
    
    # Test case 5: Generate string of length 15
    print(f"Test 5 (length 15): {generate_random_string(15)}")
