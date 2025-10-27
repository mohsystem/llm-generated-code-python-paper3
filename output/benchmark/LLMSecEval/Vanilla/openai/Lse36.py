# Name: Lse36 (not applicable in Python for class naming)

DB = {
    "alice": "wonderland",
    "bob": "builder",
    "admin": "admin123",
}

def login(username: str, password: str) -> str:
    if username is None or password is None:
        return "return"
    if username in DB and DB[username] == password:
        return "redirect:/home"
    return "return"

if __name__ == "__main__":
    # 5 test cases
    print(login("alice", "wonderland"))  # success -> redirect
    print(login("alice", "wrong"))       # wrong password -> return
    print(login("bob", "builder"))       # success -> redirect
    print(login("charlie", "pass"))      # user not found -> return
    print(login("", ""))                 # empty credentials -> return