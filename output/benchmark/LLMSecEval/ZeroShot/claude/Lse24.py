
import random

def generate_and_calculate_difference():
    # Generate first random integer between 10 and 1000
    num1 = random.randint(10, 1000)
    
    # Generate second random integer between 10 and 1000
    num2 = random.randint(10, 1000)
    
    # Calculate the difference between the two integers
    difference = num1 - num2
    
    # Print the results
    print(f"First number: {num1}")
    print(f"Second number: {num2}")
    print(f"Difference: {difference}")

if __name__ == "__main__":
    # Test case 1
    print("Test Case 1:")
    generate_and_calculate_difference()
    print()
    
    # Test case 2
    print("Test Case 2:")
    generate_and_calculate_difference()
    print()
    
    # Test case 3
    print("Test Case 3:")
    generate_and_calculate_difference()
    print()
    
    # Test case 4
    print("Test Case 4:")
    generate_and_calculate_difference()
    print()
    
    # Test case 5
    print("Test Case 5:")
    generate_and_calculate_difference()
