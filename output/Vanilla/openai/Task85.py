import secrets
import string

ALPHABET = string.ascii_letters

def random_ascii_letters(length: int) -> str:
    if length < 0:
        raise ValueError("length must be non-negative")
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))

if __name__ == "__main__":
    tests = [0, 1, 8, 16, 32]
    for n in tests:
        s = random_ascii_letters(n)
        print(f"{n}: {s}")