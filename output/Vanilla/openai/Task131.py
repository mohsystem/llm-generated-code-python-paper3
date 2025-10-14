from dataclasses import dataclass

@dataclass
class User:
    name: str = ""
    age: int = -1
    email: str = ""

def deserialize_user(input_str: str) -> User:
    user = User()
    if input_str is None:
        return user
    for token in input_str.split(';'):
        if not token:
            continue
        if '=' not in token:
            continue
        key, value = token.split('=', 1)
        key = key.strip().lower()
        value = value.strip()
        if key == 'name':
            user.name = value
        elif key == 'age':
            try:
                user.age = int(value)
            except ValueError:
                user.age = -1
        elif key == 'email':
            user.email = value
        else:
            pass
    return user

def main():
    tests = [
        "name=Alice; age=30; email=alice@example.com",
        "age=25;name=Bob;email=bob@domain.org",
        "name=Charlie;email=charlie@mail.net",
        "name = Dana ; age = notanumber ; email = dana@x.y",
        "email=eve@ex.com; name=Eve; extra=ignored; age= 42 ;"
    ]
    for t in tests:
        u = deserialize_user(t)
        print(f"Input: {t}")
        print(f"Deserialized: {u}")
        print("---")

if __name__ == "__main__":
    main()