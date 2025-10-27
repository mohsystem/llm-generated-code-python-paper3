def check_mod(username, password):
    if username is None or password is None:
        return "false"
    if username == "moderator" and password == "mod123":
        return "true"
    return "false"

if __name__ == "__main__":
    print(check_mod("moderator", "mod123"))  # true
    print(check_mod("moderator", "wrong"))   # false
    print(check_mod("user", "mod123"))       # false
    print(check_mod("moderator", ""))        # false
    print(check_mod("MODERATOR", "mod123"))  # false