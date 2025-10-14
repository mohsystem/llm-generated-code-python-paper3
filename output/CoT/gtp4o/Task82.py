# Chain-of-Through process in code generation:
# 1) Problem understanding: Function to compute salted password hash and return it.
# 2) Security requirements: Use PBKDF2-HMAC-SHA256 with adequate iterations.
# 3) Secure coding generation: Use hashlib.pbkdf2_hmac with UTF-8 encoding and fixed parameters.
# 4) Code review: Ensure no weak algorithms or dynamic eval; return hex string safely.
# 5) Secure code output: 200000 iterations, 32-byte key, hex output.

import hashlib
import binascii

def compute_hash(password: str, salt: str) -> str:
    iterations = 200000
    dklen = 32
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, iterations, dklen=dklen)
    return binascii.hexlify(dk).decode('ascii')

if __name__ == "__main__":
    # 5 test cases
    print(compute_hash("password", "salt"))
    print(compute_hash("correct horse battery staple", "somesalt"))
    print(compute_hash("P@ssw0rd!", "NaCl"))
    print(compute_hash("", "salt"))
    print(compute_hash("password", ""))