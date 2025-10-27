import os
import base64
import hashlib

def register_user(db_path: str, username: str, password: str) -> str:
    try:
        if username is None or username.strip() == "":
            return "ERROR: Username cannot be empty"
        if password is None or password == "":
            return "ERROR: Password cannot be empty"
        username = username.strip()

        if not os.path.exists(db_path):
            # Ensure directory exists if needed
            parent = os.path.dirname(os.path.abspath(db_path))
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(db_path, "w", encoding="utf-8") as _:
                pass

        # Check uniqueness
        with open(db_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) >= 1 and parts[0] == username:
                    return "ERROR: Username already exists"

        # Salt and hash
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        h = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

        # Append record
        with open(db_path, "a", encoding="utf-8") as f:
            f.write(f"{username},{salt_b64},{h}\n")

        return "OK: User registered"
    except Exception as e:
        return f"ERROR: {e}"

if __name__ == "__main__":
    db = "users_py.csv"
    print(register_user(db, "alice", "password123"))
    print(register_user(db, "bob", "Secr3t!"))
    print(register_user(db, "charlie", "hunter2"))
    print(register_user(db, "alice", "anotherpass"))  # duplicate
    print(register_user(db, "dave", ""))  # empty password