import random

def generate_random_float_strings():
    """
    Generates three random float numbers and converts them to strings.

    Returns:
        A list of three strings, each representing a random float.
    """
    # Generate three random floats between 0.0 and 1.0
    f1 = random.random()
    f2 = random.random()
    f3 = random.random()

    # Convert floats to strings using %-formatting (similar to sprintf)
    string1 = "%f" % f1
    string2 = "%f" % f2
    string3 = "%f" % f3
    
    return [string1, string2, string3]

if __name__ == '__main__':
    print("Running 5 test cases for Python:")
    for i in range(5):
        random_strings = generate_random_float_strings()
        print(f"Test Case {i + 1}: {random_strings}")