import secrets
import string
from typing import Final

LETTERS: Final[str] = string.ascii_letters
MAX_LEN: Final[int] = 1_000_000

def random_ascii_letters(length: int) -> str:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0 or length > MAX_LEN:
        raise ValueError(f"length must be in range [0, {MAX_LEN}]")
    # secrets.choice uses a CSPRNG; selecting from ascii_letters ensures only letters are used.
    return ''.join(secrets.choice(LETTERS) for _ in range(length))

if __name__ == "__main__":
    tests = [0, 1, 10, 32, 100]
    for t in tests:
        s = random_ascii_letters(t)
        print(f"len={t} str={s}")