import random

def generate_and_calculate_difference():
    """
    Generates two random integers between 10 and 1000, calculates their
    difference, and prints the results.
    """
    # Generate the first random integer between 10 and 1000 (inclusive).
    num1 = random.randint(10, 1000)

    # Generate the second random integer between 10 and 1000 (inclusive).
    num2 = random.randint(10, 1000)

    # Calculate the difference between the two integers.
    difference = num1 - num2

    # Print the results.
    print(f"First number: {num1}")
    print(f"Second number: {num2}")
    print(f"Difference (First - Second): {difference}")

def main():
    """
    Main function to run 5 test cases.
    """
    print("Running 5 test cases:")
    for i in range(5):
        print(f"--- Test Case {i + 1} ---")
        generate_and_calculate_difference()

if __name__ == "__main__":
    main()