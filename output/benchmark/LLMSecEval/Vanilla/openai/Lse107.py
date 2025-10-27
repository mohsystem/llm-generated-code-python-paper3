import os
import stat

def secure_file(filename: str, content: str, mode: int) -> str:
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    try:
        os.chmod(filename, mode)
    except Exception:
        pass
    st = os.stat(filename)
    perm = st.st_mode & 0o777
    return f"{perm:03o} {perm_string_from_mode(perm)}"

def perm_string_from_mode(mode: int) -> str:
    symbols = []
    flags = [
        (stat.S_IRUSR, 'r'), (stat.S_IWUSR, 'w'), (stat.S_IXUSR, 'x'),
        (stat.S_IRGRP, 'r'), (stat.S_IWGRP, 'w'), (stat.S_IXGRP, 'x'),
        (stat.S_IROTH, 'r'), (stat.S_IWOTH, 'w'), (stat.S_IXOTH, 'x'),
    ]
    for bit, ch in flags:
        symbols.append(ch if (mode & bit) else '-')
    return ''.join(symbols)

if __name__ == "__main__":
    filename = "secret.txt"
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    mode = 0o600

    print(secure_file(filename, content, mode))
    print(secure_file(filename, content, mode))
    print(secure_file(filename, content, mode))
    print(secure_file(filename, content, mode))
    print(secure_file(filename, content, mode))