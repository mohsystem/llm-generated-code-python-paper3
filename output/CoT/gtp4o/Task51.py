# Chain-of-Through secure implementation for a simple Caesar cipher.
# 1) Problem understanding: Provide encryption for a given string via Caesar cipher.
# 2) Security requirements: Handle None input; avoid side effects.
# 3) Secure coding generation: Normalize key properly, preserve non-alpha chars.
# 4) Code review: Ensure correct wrap-around and character domain checks.
# 5) Secure code output: Finalized implementation.
def encrypt(text: str, key: int) -> str:
    if text is None:
        text = ""
    k = key % 26
    if k < 0:
        k += 26
    out_chars = []
    for c in text:
        oc = ord(c)
        if 65 <= oc <= 90:
            out_chars.append(chr(65 + ((oc - 65 + k) % 26)))
        elif 97 <= oc <= 122:
            out_chars.append(chr(97 + ((oc - 97 + k) % 26)))
        else:
            out_chars.append(c)
    return "".join(out_chars)

if __name__ == "__main__":
    tests = [
        ("Hello, World!", 3),
        ("abcxyz ABCXYZ", 2),
        ("Attack at dawn! 123", 5),
        ("", 10),
        ("Zebra-123", -1),
    ]
    for s, k in tests:
        print(f"Input: {s} | Key: {k} | Encrypted: {encrypt(s, k)}")