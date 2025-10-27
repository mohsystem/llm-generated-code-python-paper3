def login(username, password):
    try:
        if username is None or password is None:
            raise Exception("Null credentials")
        if username == "error" or password == "error":
            raise Exception("Forced error")
        db = {
            "alice": "password123",
            "bob": "qwerty",
            "charlie": "letmein",
        }
        if username in db and db[username] == password:
            return "success"
        return "cant_login"
    except Exception:
        return "internal_server_error"


if __name__ == "__main__":
    print(login("alice", "password123"))  # success
    print(login("alice", "wrong"))        # cant_login
    print(login("unknown", "pass"))       # cant_login
    print(login(None, "pass"))            # internal_server_error
    print(login("error", "x"))            # internal_server_error