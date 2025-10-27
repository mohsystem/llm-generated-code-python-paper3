import random

def generate_random_float_strings():
    """
    Generates three random floats and converts them to strings.
    :return: A list of three strings, each representing a random float.
    """
    f1 = random.random()
    f2 = random.random()
    f3 = random.random()
    
    # Using %-formatting which is similar to C's sprintf
    string1 = "%f" % f1
    string2 = "%f" % f2
    string3 = "%f" % f3
    
    return [string1, string2, string3]

if __name__ == "__main__":
    print("Python Test Cases:")
    for i in range(5):
        print(f"Test Case {i + 1}: {generate_random_float_strings()}")