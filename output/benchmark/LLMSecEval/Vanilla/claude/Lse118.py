
import random

def write_random_floats_to_file(filename):
    # Generate 3 random floats
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()
    
    # Convert them to strings
    str1 = str(float1)
    str2 = str(float2)
    str3 = str(float3)
    
    # Concatenate them into a single string
    concatenated = str1 + str2 + str3
    
    # Write the string to a file
    with open(filename, 'w') as file:
        file.write(concatenated)

if __name__ == "__main__":
    # Test case 1
    write_random_floats_to_file("output1.txt")
    
    # Test case 2
    write_random_floats_to_file("output2.txt")
    
    # Test case 3
    write_random_floats_to_file("output3.txt")
    
    # Test case 4
    write_random_floats_to_file("output4.txt")
    
    # Test case 5
    write_random_floats_to_file("output5.txt")
    
    print("Files created successfully!")
