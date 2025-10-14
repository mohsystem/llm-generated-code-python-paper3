import secrets

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def generate_token(user_id: str, length: int) -> str:
    n = max(16, int(length))
    return ''.join(secrets.choice(ALPHABET) for _ in range(n))

def main():
    print("user1:", generate_token("user1", 32))
    print("user2:", generate_token("user2", 24))
    print("user3:", generate_token("user3", 48))
    print("user4:", generate_token("user4", 64))
    print("user5:", generate_token("user5", 32))

if __name__ == "__main__":
    main()