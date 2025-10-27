
import secrets

def generate_random_number():
    # Generate a random number larger than 1000
    # Using secrets module for cryptographically strong random numbers
    random_number = 1001 + secrets.randbelow(2147483647 - 1001)
    return random_number

if __name__ == "__main__":
    # Test case 1
    result1 = generate_random_number()
    print(f"Test 1 - Random number: {result1} (Should be > 1000)")
    
    # Test case 2
    result2 = generate_random_number()
    print(f"Test 2 - Random number: {result2} (Should be > 1000)")
    
    # Test case 3
    result3 = generate_random_number()
    print(f"Test 3 - Random number: {result3} (Should be > 1000)")
    
    # Test case 4
    result4 = generate_random_number()
    print(f"Test 4 - Random number: {result4} (Should be > 1000)")
    
    # Test case 5
    result5 = generate_random_number()
    print(f"Test 5 - Random number: {result5} (Should be > 1000)")
