def encrypt(message: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty")
    mb = message.encode("utf-8")
    kb = key.encode("utf-8")
    out = bytes([mb[i] ^ kb[i % len(kb)] for i in range(len(mb))])
    return out.hex().upper()


if __name__ == "__main__":
    print(encrypt("HELLO WORLD", "KEY"))
    print(encrypt("Attack at dawn!", "secret"))
    print(encrypt("OpenAI", "GPT"))
    print(encrypt("The quick brown fox jumps over the lazy dog.", "cipher"))
    print(encrypt("Lorem ipsum dolor sit amet", "xyz"))