import secrets
import string

def generate_random_string(length: int) -> str:
    if not isinstance(length, int):
        raise TypeError("length must be an int")
    if length < 0:
        raise ValueError("length must be non-negative")
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    tests = [0, 1, 16, 32, 100]
    for t in tests:
        print(f"{t}: {generate_random_string(t)}")