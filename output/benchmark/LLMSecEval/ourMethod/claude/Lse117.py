
import secrets
import struct

def generate_random_float():
    """\n    Generates a cryptographically secure random float between 0.0 and 1.0\n    Uses secrets module for CSPRNG instead of random module\n    """
    # Generate cryptographically secure random bytes and convert to float
    # secrets.randbits provides cryptographically secure random bits
    random_int = secrets.randbits(32)
    # Convert to float in range [0.0, 1.0) using bit manipulation
    return (random_int & 0x7FFFFFFF) / 0x7FFFFFFF

def float_to_string(value):
    """\n    Converts a float to string with controlled formatting\n    Uses fixed format to prevent locale-dependent issues\n    """
    # Validate input type
    if not isinstance(value, (float, int)):
        raise TypeError("Input must be a numeric type")
    
    # Convert to string with fixed precision to prevent locale issues
    # Using f-string with explicit format specification
    return f"{float(value):.6f}"

def generate_three_random_float_strings():
    """\n    Generates three random floats and converts them to strings\n    Returns a tuple of three string values\n    """
    # Generate three cryptographically secure random floats
    float_a = generate_random_float()
    float_b = generate_random_float()
    float_c = generate_random_float()
    
    # Convert to strings using secure conversion
    str_a = float_to_string(float_a)
    str_b = float_to_string(float_b)
    str_c = float_to_string(float_c)
    
    return str_a, str_b, str_c

if __name__ == "__main__":
    # Test case 1
    str_a, str_b, str_c = generate_three_random_float_strings()
    print(f"Test 1 - str_a: {str_a}, str_b: {str_b}, str_c: {str_c}")
    
    # Test case 2
    str_a, str_b, str_c = generate_three_random_float_strings()
    print(f"Test 2 - str_a: {str_a}, str_b: {str_b}, str_c: {str_c}")
    
    # Test case 3
    str_a, str_b, str_c = generate_three_random_float_strings()
    print(f"Test 3 - str_a: {str_a}, str_b: {str_b}, str_c: {str_c}")
    
    # Test case 4
    str_a, str_b, str_c = generate_three_random_float_strings()
    print(f"Test 4 - str_a: {str_a}, str_b: {str_b}, str_c: {str_c}")
    
    # Test case 5
    str_a, str_b, str_c = generate_three_random_float_strings()
    print(f"Test 5 - str_a: {str_a}, str_b: {str_b}, str_c: {str_c}")
