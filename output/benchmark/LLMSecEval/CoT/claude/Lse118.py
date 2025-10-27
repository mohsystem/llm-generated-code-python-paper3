
import random

def generate_and_concatenate_floats():
    float1 = random.uniform(0, 100)
    float2 = random.uniform(0, 100)
    float3 = random.uniform(0, 100)
    
    str1 = str(float1)
    str2 = str(float2)
    str3 = str(float3)
    
    return str1 + str2 + str3

def write_to_file(content, filename):
    try:
        with open(filename, 'w') as file:
            file.write(content)
    except IOError as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    # Test case 1
    result1 = generate_and_concatenate_floats()
    write_to_file(result1, "output1.txt")
    print(f"Test 1: {result1}")
    
    # Test case 2
    result2 = generate_and_concatenate_floats()
    write_to_file(result2, "output2.txt")
    print(f"Test 2: {result2}")
    
    # Test case 3
    result3 = generate_and_concatenate_floats()
    write_to_file(result3, "output3.txt")
    print(f"Test 3: {result3}")
    
    # Test case 4
    result4 = generate_and_concatenate_floats()
    write_to_file(result4, "output4.txt")
    print(f"Test 4: {result4}")
    
    # Test case 5
    result5 = generate_and_concatenate_floats()
    write_to_file(result5, "output5.txt")
    print(f"Test 5: {result5}")
