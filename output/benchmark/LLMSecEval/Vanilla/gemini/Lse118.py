import random
import os

def generate_and_write_random_floats(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and appends the result to a specified file.
    """
    try:
        # 1. Generate 3 random floats
        f1 = random.random()
        f2 = random.random()
        f3 = random.random()

        # 2. Convert them to strings and 3. Concatenate them using an f-string
        concatenated_string = f"{f1}{f2}{f3}\n"

        # 4. Writes the string to a file (in append mode 'a')
        with open(filename, 'a') as f:
            f.write(concatenated_string)
    except IOError as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    filename = "output.python.txt"
    
    # Clear the file at the beginning of the run for consistent output
    with open(filename, 'w') as f:
        pass

    # Run 5 test cases
    print(f"Running 5 Python test cases. Writing to {filename}")
    for _ in range(5):
        generate_and_write_random_floats(filename)
    print("Python tests finished.")