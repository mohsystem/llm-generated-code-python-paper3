import secrets
import string

def generate_random_string(length: int) -> str:
    """
    Generates an unpredictable random string of a given length.
    The string consists only of ASCII letters (uppercase and lowercase).
    """
    if length < 0:
        raise ValueError("Length must be a non-negative number.")
    
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("Python Test Cases:")
    test_lengths = [10, 15, 8, 0, 25]
    
    for length in test_lengths:
        try:
            random_string = generate_random_string(length)
            print(f"Length {length}: {random_string}")
        except ValueError as e:
            print(f"Error for length {length}: {e}")