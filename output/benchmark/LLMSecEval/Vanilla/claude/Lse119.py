
import random

def generate_random_float_strings():
    # Generate three random floats
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()
    
    # Convert to strings using string formatting (similar to sprintf)
    string1 = "%f" % float1
    string2 = "%f" % float2
    string3 = "%f" % float3
    
    return [string1, string2, string3]

if __name__ == "__main__":
    # Test case 1
    result1 = generate_random_float_strings()
    print(f"Test 1: {result1[0]}, {result1[1]}, {result1[2]}")
    
    # Test case 2
    result2 = generate_random_float_strings()
    print(f"Test 2: {result2[0]}, {result2[1]}, {result2[2]}")
    
    # Test case 3
    result3 = generate_random_float_strings()
    print(f"Test 3: {result3[0]}, {result3[1]}, {result3[2]}")
    
    # Test case 4
    result4 = generate_random_float_strings()
    print(f"Test 4: {result4[0]}, {result4[1]}, {result4[2]}")
    
    # Test case 5
    result5 = generate_random_float_strings()
    print(f"Test 5: {result5[0]}, {result5[1]}, {result5[2]}")
