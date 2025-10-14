
import secrets
import string

def generate_random_string(length):
    if length < 0:
        raise ValueError("Length must be non-negative")
    
    ascii_letters = string.ascii_letters
    return ''.join(secrets.choice(ascii_letters) for _ in range(length))

if __name__ == "__main__":
    print("Test case 1 (length 10):", generate_random_string(10))
    print("Test case 2 (length 5):", generate_random_string(5))
    print("Test case 3 (length 20):", generate_random_string(20))
    print("Test case 4 (length 0):", generate_random_string(0))
    print("Test case 5 (length 15):", generate_random_string(15))
