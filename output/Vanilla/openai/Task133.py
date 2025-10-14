def reset_password(users, username, old_pass, new_pass, confirm_pass):
    if username is None or old_pass is None or new_pass is None or confirm_pass is None:
        return "ERROR: Invalid input."
    if username not in users:
        return "ERROR: User not found."
    if users[username] != old_pass:
        return "ERROR: Old password is incorrect."
    if new_pass != confirm_pass:
        return "ERROR: New password and confirmation do not match."
    if new_pass == old_pass:
        return "ERROR: New password must be different from old password."
    if len(new_pass) < 8:
        return "ERROR: Password must be at least 8 characters long."
    if not any(c.islower() for c in new_pass) or not any(c.isupper() for c in new_pass) or not any(c.isdigit() for c in new_pass) or not any(not c.isalnum() for c in new_pass):
        return "ERROR: Password must include uppercase, lowercase, digit, and special character."
    if username.lower() in new_pass.lower():
        return "ERROR: Password must not contain the username."
    users[username] = new_pass
    return "SUCCESS: Password updated."


if __name__ == "__main__":
    users = {
        "alice": "OldPass1!",
        "bob": "Bob#2020",
        "carol": "Car0l@123",
    }

    # Test 1: Successful reset for alice
    print(reset_password(users, "alice", "OldPass1!", "NewStrong1$", "NewStrong1$"))

    # Test 2: Wrong old password for bob
    print(reset_password(users, "bob", "wrong", "BobNew#2024", "BobNew#2024"))

    # Test 3: Confirm mismatch for carol
    print(reset_password(users, "carol", "Car0l@123", "Another1!", "Mismatch1!"))

    # Test 4: Unknown user dave
    print(reset_password(users, "dave", "anything", "SomePass1!", "SomePass1!"))

    # Test 5: Weak password for alice after successful change (note old is updated)
    print(reset_password(users, "alice", "NewStrong1$", "short", "short"))