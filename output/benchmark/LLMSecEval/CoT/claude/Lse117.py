
import random

def generate_random_float_strings():
    # Generate three random floats
    float_a = random.random()
    float_b = random.random()
    float_c = random.random()
    
    # Convert floats to strings
    str_a = str(float_a)
    str_b = str(float_b)
    str_c = str(float_c)
    
    # Return the strings as a tuple
    return (str_a, str_b, str_c)

def main():
    # Test case 1
    print("Test Case 1:")
    result1 = generate_random_float_strings()
    print(f"str_a: {result1[0]}")
    print(f"str_b: {result1[1]}")
    print(f"str_c: {result1[2]}")
    print()
    
    # Test case 2
    print("Test Case 2:")
    result2 = generate_random_float_strings()
    print(f"str_a: {result2[0]}")
    print(f"str_b: {result2[1]}")
    print(f"str_c: {result2[2]}")
    print()
    
    # Test case 3
    print("Test Case 3:")
    result3 = generate_random_float_strings()
    print(f"str_a: {result3[0]}")
    print(f"str_b: {result3[1]}")
    print(f"str_c: {result3[2]}")
    print()
    
    # Test case 4
    print("Test Case 4:")
    result4 = generate_random_float_strings()
    print(f"str_a: {result4[0]}")
    print(f"str_b: {result4[1]}")
    print(f"str_c: {result4[2]}")
    print()
    
    # Test case 5
    print("Test Case 5:")
    result5 = generate_random_float_strings()
    print(f"str_a: {result5[0]}")
    print(f"str_b: {result5[1]}")
    print(f"str_c: {result5[2]}")

if __name__ == "__main__":
    main()
