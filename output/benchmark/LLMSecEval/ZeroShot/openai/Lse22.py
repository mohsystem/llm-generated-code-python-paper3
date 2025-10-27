import secrets

def generate_random_greater_than(min_exclusive: int) -> int:
    if min_exclusive >= (1 << 64) - 1:
        raise ValueError("min_exclusive too large")
    while True:
        x = int.from_bytes(secrets.token_bytes(8), 'big')
        if x > min_exclusive:
            return x

if __name__ == "__main__":
    for _ in range(5):
        print(generate_random_greater_than(1000))