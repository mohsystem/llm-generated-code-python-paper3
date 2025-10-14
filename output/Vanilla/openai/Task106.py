def modexp(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)

def encrypt_rsa(message: int, e: int, n: int) -> int:
    return modexp(message, e, n)

def decrypt_rsa(ciphertext: int, d: int, n: int) -> int:
    return modexp(ciphertext, d, n)

if __name__ == "__main__":
    n = 3233
    e = 17
    d = 2753

    messages = [65, 42, 123, 999, 2021]
    for m in messages:
        c = encrypt_rsa(m, e, n)
        p = decrypt_rsa(c, d, n)
        print(f"Message: {m} -> Cipher: {c} -> Decrypted: {p}")