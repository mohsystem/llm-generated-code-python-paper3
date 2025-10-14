import secrets

LETTERS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALPHABET = len(LETTERS)  # 52
M = 256 - (256 % ALPHABET)  # 208 to avoid modulo bias

def generate_random_string(length: int) -> str:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length == 0:
        return ""
    out = bytearray()
    while len(out) < length:
        buf = secrets.token_bytes(64)
        for b in buf:
            if b < M:
                out.append(LETTERS[b % ALPHABET])
                if len(out) == length:
                    break
    return out.decode("ascii")

if __name__ == "__main__":
    tests = [0, 1, 10, 32, 64]
    for t in tests:
        s = generate_random_string(t)
        print(f"{t}: {s}")