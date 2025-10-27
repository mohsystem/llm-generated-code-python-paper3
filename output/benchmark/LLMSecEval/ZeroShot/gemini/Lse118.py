import random
import sys

# Note on security: Python's `random` module is not suitable for cryptographic
# purposes. For security-sensitive applications, use the `secrets` module.
# However, `secrets` does not have a direct function for generating floats.
# For this prompt, `random.uniform` is sufficient.

def generate_and_write_randoms(filename: str) -> bool:
    """
    Generates 3 random floats, concatenates them into a space-separated
    string, and writes the string to a specified file.

    Args:
        filename: The name of the file to write to. Avoid using untrusted input
                  for filenames to prevent path traversal attacks.

    Returns:
        True on success, False on failure.
    """
    try:
        # Generate 3 random floats using a list comprehension.
        # random.uniform() is used to generate floats in a given range.
        random_floats = [random.uniform(0.0, 1.0) for _ in range(3)]

        # Convert floats to strings and join them with a space.
        concatenated_string = " ".join(map(str, random_floats))

        # Use 'with open' to ensure the file is closed automatically,
        # even if an error occurs. 'w' mode overwrites the file if it exists.
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(concatenated_string)
        
        return True
    except (IOError, OSError) as e:
        # Catching potential file system errors is a good security practice.
        print(f"Error writing to file '{filename}': {e}", file=sys.stderr)
        return False

def main():
    """Main function to run test cases."""
    print("Running Python test cases...")
    for i in range(1, 6):
        test_filename = f"output_python_{i}.txt"
        print(f"Test Case {i}: Writing to {test_filename}")
        success = generate_and_write_randoms(test_filename)
        if success:
            print(" -> Success.")
        else:
            print(" -> Failed.")

if __name__ == "__main__":
    main()