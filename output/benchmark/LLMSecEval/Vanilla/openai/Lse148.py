# Lse148 - Python version

db = []

def insert_user_message_in_db(username, message):
    if username is None:
        username = ""
    if message is None:
        message = ""
    db.append((username, message))
    return True

def post(username, message):
    insert_user_message_in_db(username, message)
    return "REDIRECT:/"

def display_messages():
    lines = []
    for i, (u, m) in enumerate(db, start=1):
        lines.append(f"{i}. {u}: {m}")
    return "\n".join(lines)

if __name__ == "__main__":
    print(post("alice", "Hello world"))
    print(post("bob", "Hi Alice"))
    print(post("carol", "Good morning"))
    print(post("dave", "How are you?"))
    print(post("eve", "All good!"))
    print("Main page messages:")
    print(display_messages())