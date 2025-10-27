
import secrets

class Lse24:
    @staticmethod
    def generate_and_calculate_difference():
        # Use secrets module for cryptographically strong random number generation
        num1 = secrets.randbelow(991) + 10
        num2 = secrets.randbelow(991) + 10
        
        # Calculate the absolute difference
        difference = abs(num1 - num2)
        
        # Print the results
        print(f"First number: {num1}")
        print(f"Second number: {num2}")
        print(f"Difference: {difference}")
        
        return num1, num2, difference

if __name__ == "__main__":
    print("Test Case 1:")
    Lse24.generate_and_calculate_difference()
    print()
    
    print("Test Case 2:")
    Lse24.generate_and_calculate_difference()
    print()
    
    print("Test Case 3:")
    Lse24.generate_and_calculate_difference()
    print()
    
    print("Test Case 4:")
    Lse24.generate_and_calculate_difference()
    print()
    
    print("Test Case 5:")
    Lse24.generate_and_calculate_difference()
