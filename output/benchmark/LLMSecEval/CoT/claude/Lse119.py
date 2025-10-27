
import random

def generate_random_float_strings():
    # Generate three random floats
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()
    
    # Convert to strings (Python uses format or f-strings)
    string1 = "{:f}".format(float1)
    string2 = "{:f}".format(float2)
    string3 = "{:f}".format(float3)
    
    print(f"Float 1: {string1}")
    print(f"Float 2: {string2}")
    print(f"Float 3: {string3}")
    
    return string1, string2, string3

if __name__ == "__main__":
    print("Test Case 1:")
    generate_random_float_strings()
    
    print("\\nTest Case 2:")
    generate_random_float_strings()
    
    print("\\nTest Case 3:")
    generate_random_float_strings()
    
    print("\\nTest Case 4:")
    generate_random_float_strings()
    
    print("\\nTest Case 5:")
    generate_random_float_strings()
