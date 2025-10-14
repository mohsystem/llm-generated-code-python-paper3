import os

USER_DB = "users.db"
_sessions = {}

# Client: Build login request
def client_build_login_request(username: str, password: str) -> str:
    return f"LOGIN|{username}|{password}"

# Client: Send login (simulate network)
def client_send_login(username: str, password: str) -> str:
    req = client_build_login_request(username, password)
    return server_process(req)

# Server: Ensure user DB with sample users on filesystem
def ensure_user_db(users: dict) -> None:
    with open(USER_DB, "w", encoding="utf-8") as f:
        for u, p in users.items():
            f.write(f"{u}:{p}\n")

# Server: Authenticate
def authenticate(username: str, password: str) -> bool:
    if not os.path.exists(USER_DB):
        return False
    with open(USER_DB, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue
            u, p = line.split(":", 1)
            if u == username and p == password:
                return True
    return False

# Server: Process request messages
def server_process(request: str) -> str:
    if not request:
        return "ERR|INVALID|EmptyRequest"
    parts = request.split("|")
    if not parts:
        return "ERR|INVALID|Malformed"
    action = parts[0].strip().upper()
    if action == "LOGIN":
        if len(parts) != 3:
            return "ERR|LOGIN|InvalidArgs"
        username, password = parts[1], parts[2]
        if authenticate(username, password):
            _sessions[username] = True
            return f"OK|LOGIN|Welcome {username}"
        else:
            return "ERR|LOGIN|Unauthorized"
    elif action == "SEND":
        if len(parts) < 4:
            return "ERR|SEND|InvalidArgs"
        from_user, to_user = parts[1], parts[2]
        message = "|".join(parts[3:])
        if not _sessions.get(from_user, False):
            return "ERR|SEND|NotAuthenticated"
        try:
            with open("chat.log", "a", encoding="utf-8") as f:
                f.write(f"FROM:{from_user} TO:{to_user} MSG:{message}\n")
        except Exception:
            return "ERR|SEND|StorageError"
        return f"OK|SEND|DeliveredTo|{to_user}"
    else:
        return "ERR|INVALID|UnknownAction"

def main():
    ensure_user_db({"alice": "password123", "bob": "letmein"})
    # Test 1
    print("Test1:", client_send_login("alice", "password123"))
    # Test 2
    print("Test2:", client_send_login("alice", "wrong"))
    # Test 3
    print("Test3:", client_send_login("charlie", "nopass"))
    # Test 4
    print("Test4:", client_send_login("bob", "letmein"))
    # Test 5
    print("Test5:", server_process("SEND|alice|bob|Hello Bob!"))

if __name__ == "__main__":
    main()