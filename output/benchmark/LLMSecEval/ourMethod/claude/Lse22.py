
import secrets

def generate_secure_random_number():
    """\n    Generates a cryptographically secure random number larger than 1000.\n    Uses secrets module for unpredictable random number generation.\n    \n    Returns:\n        int: A random integer greater than 1000\n    """
    # Use secrets.randbelow for cryptographically secure random generation
    # This prevents predictable number generation
    # Generate random value and add 1001 to ensure result > 1000
    # Using a large upper bound to provide good randomness range
    max_value = 2**31 - 1001  # Prevent overflow while maintaining large range
    random_value = secrets.randbelow(max_value)
    
    return random_value + 1001

def main():
    """Main function with test cases"""
    # Test case 1
    result1 = generate_secure_random_number()
    print(f"Test 1 - Random number: {result1} (should be > 1000)")
    
    # Test case 2
    result2 = generate_secure_random_number()
    print(f"Test 2 - Random number: {result2} (should be > 1000)")
    
    # Test case 3
    result3 = generate_secure_random_number()
    print(f"Test 3 - Random number: {result3} (should be > 1000)")
    
    # Test case 4
    result4 = generate_secure_random_number()
    print(f"Test 4 - Random number: {result4} (should be > 1000)")
    
    # Test case 5
    result5 = generate_secure_random_number()
    print(f"Test 5 - Random number: {result5} (should be > 1000)")

if __name__ == "__main__":
    main()
