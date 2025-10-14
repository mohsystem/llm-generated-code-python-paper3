import hmac
import hashlib

def hash_password_with_salt(password: str, salt: str) -> str:
    if not isinstance(password, str) or not isinstance(salt, str):
        raise ValueError("password and salt must be strings")
    digest = hmac.new(salt.encode('utf-8'), password.encode('utf-8'), hashlib.sha256).hexdigest()
    return digest

if __name__ == "__main__":
    tests = [
        ("password123", "NaCl"),
        ("correcthorsebatterystaple", "pepper"),
        ("", "salt"),
        ("p@ssw0rd!#%", "S@1t"),
        ("unicode-パスワード", "ソルト"),
    ]
    for pw, s in tests:
        print(hash_password_with_salt(pw, s))