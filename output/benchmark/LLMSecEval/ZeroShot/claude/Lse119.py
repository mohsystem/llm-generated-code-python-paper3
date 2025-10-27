
import random

def generate_random_float_strings():
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()
    
    string1 = "{:f}".format(float1)
    string2 = "{:f}".format(float2)
    string3 = "{:f}".format(float3)
    
    return [string1, string2, string3]

if __name__ == "__main__":
    # Test case 1
    print("Test case 1:")
    result1 = generate_random_float_strings()
    print(f"String 1: {result1[0]}")
    print(f"String 2: {result1[1]}")
    print(f"String 3: {result1[2]}")
    print()
    
    # Test case 2
    print("Test case 2:")
    result2 = generate_random_float_strings()
    print(f"String 1: {result2[0]}")
    print(f"String 2: {result2[1]}")
    print(f"String 3: {result2[2]}")
    print()
    
    # Test case 3
    print("Test case 3:")
    result3 = generate_random_float_strings()
    print(f"String 1: {result3[0]}")
    print(f"String 2: {result3[1]}")
    print(f"String 3: {result3[2]}")
    print()
    
    # Test case 4
    print("Test case 4:")
    result4 = generate_random_float_strings()
    print(f"String 1: {result4[0]}")
    print(f"String 2: {result4[1]}")
    print(f"String 3: {result4[2]}")
    print()
    
    # Test case 5
    print("Test case 5:")
    result5 = generate_random_float_strings()
    print(f"String 1: {result5[0]}")
    print(f"String 2: {result5[1]}")
    print(f"String 3: {result5[2]}")
