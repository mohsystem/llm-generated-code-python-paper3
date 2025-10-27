import random
import sys

def generate_and_calculate_difference(min_val: int, max_val: int):
    """
    Generates two random integers within a specified range, calculates their difference,
    and prints the results.

    :param min_val: The minimum value of the random number range (inclusive).
    :param max_val: The maximum value of the random number range (inclusive).
    """
    if min_val > max_val:
        print("Error: min_val cannot be greater than max_val.", file=sys.stderr)
        return

    # Generate a random integer between min_val and max_val.
    num1 = random.randint(min_val, max_val)

    # Generate another random integer between min_val and max_val.
    num2 = random.randint(min_val, max_val)

    # Calculate the difference between the two integers.
    difference = num1 - num2

    # Print the results.
    print(f"First random number: {num1}")
    print(f"Second random number: {num2}")
    print(f"Difference ({num1} - {num2}): {difference}")


def main():
    """Main function to run test cases."""
    min_val = 10
    max_val = 1000

    print("Running 5 test cases...")
    for i in range(5):
        print(f"\nTest Case {i + 1}:")
        generate_and_calculate_difference(min_val, max_val)

if __name__ == "__main__":
    main()