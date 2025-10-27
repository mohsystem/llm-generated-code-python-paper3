import re

# In-memory "database": username -> hashed_password
DB = {}

FNV_OFFSET_BASIS = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
HASH_ITERATIONS = 10000
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')

def add_user(username: str, password: str) -> None:
    if not is_valid_username(username):
        return
    DB[username] = hash_password(username, password)

def login(username: str, password: str) -> str:
    if username is None or password is None:
        return "redirect:/login"
    if not is_valid_username(username):
        return "redirect:/login"
    stored = DB.get(username)
    if stored is None:
        return "redirect:/login"
    provided = hash_password(username, password)
    if secure_equals(stored, provided):
        return "redirect:/home"
    else:
        return "redirect:/login"

def is_valid_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.fullmatch(username or ""))

def hash_password(username: str, password: str) -> str:
    salt = "s@lt-" + username
    data = (salt + ":" + password).encode("utf-8")
    h = FNV_OFFSET_BASIS
    mask = 0xFFFFFFFFFFFFFFFF
    for i in range(HASH_ITERATIONS):
        for b in data:
            h ^= b
            h = (h * FNV_PRIME) & mask
        # Mix iteration counter
        for shift in (0, 8, 16, 24):
            h ^= (i >> shift) & 0xFF
            h = (h * FNV_PRIME) & mask
    return f"{h:016x}"

def secure_equals(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    diff = len(a) ^ len(b)
    max_len = max(len(a), len(b))
    for i in range(max_len):
        ca = ord(a[i]) if i < len(a) else 0
        cb = ord(b[i]) if i < len(b) else 0
        diff |= (ca ^ cb)
    return diff == 0

if __name__ == "__main__":
    add_user("alice", "Pa$$w0rd!")
    add_user("bob", "secret1234")
    add_user("charlie", "CorrectHorseBatteryStaple")

    print("Test1:", login("alice", "Pa$$w0rd!"))                 # redirect:/home
    print("Test2:", login("alice", "wrong"))                      # redirect:/login
    print("Test3:", login("dave", "anything"))                    # redirect:/login
    print("Test4:", login("eve; DROP TABLE users", "x"))          # redirect:/login (invalid username)
    print("Test5:", login("bob", "secret1234"))                   # redirect:/home