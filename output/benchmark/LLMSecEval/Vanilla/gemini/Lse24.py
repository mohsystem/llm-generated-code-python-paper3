import random

def generate_and_calculate_difference():
    num1 = random.randint(10, 1000)
    num2 = random.randint(10, 1000)
    
    difference = abs(num1 - num2)
    
    print(f"First number: {num1}")
    print(f"Second number: {num2}")
    print(f"Difference: {difference}")

def main():
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        generate_and_calculate_difference()
        print()

if __name__ == "__main__":
    main()