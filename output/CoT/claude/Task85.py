
import secrets
import string

def generate_random_string(length):
    if length < 0:
        raise ValueError("Length cannot be negative")
    if length == 0:
        return ""
    if length > 1000000:
        raise ValueError("Length too large to prevent resource exhaustion")
    
    ascii_letters = string.ascii_letters
    return ''.join(secrets.choice(ascii_letters) for _ in range(length))

if __name__ == "__main__":
    print(f"Test Case 1 (length=10): {generate_random_string(10)}")
    print(f"Test Case 2 (length=5): {generate_random_string(5)}")
    print(f"Test Case 3 (length=20): {generate_random_string(20)}")
    print(f"Test Case 4 (length=1): {generate_random_string(1)}")
    print(f"Test Case 5 (length=0): '{generate_random_string(0)}'")
