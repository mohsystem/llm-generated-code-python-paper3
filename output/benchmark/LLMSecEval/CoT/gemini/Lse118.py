import random
import sys

def generate_and_write_to_file(filename):
    """
    Generates 3 random floats, concatenates them as strings,
    and writes the result to a specified file.

    Args:
        filename (str): The name of the file to write to.
    """
    try:
        # 1. Generate 3 random floats
        f1 = random.uniform(0.0, 1.0)
        f2 = random.uniform(0.0, 1.0)
        f3 = random.uniform(0.0, 1.0)

        # 2. Convert to strings and 3. Concatenate
        # Using an f-string is a modern and readable way to format strings
        concatenated_string = f"{f1}{f2}{f3}"

        # 4. Write the string to a file
        # The 'with' statement ensures the file is automatically closed,
        # even if errors occur.
        with open(filename, 'w') as f:
            f.write(concatenated_string)
        print(f"Successfully wrote to {filename}")

    except IOError as e:
        print(f"An error occurred while writing to file {filename}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    # Run 5 test cases
    print("--- Python Test Cases ---")
    for i in range(1, 6):
        filename = f"python_output_{i}.txt"
        print(f"Running test case {i}...")
        generate_and_write_to_file(filename)
        print("--------------------")