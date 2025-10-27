import os
import stat

def create_restrictive_file(path: str, content: str) -> bool:
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False

if __name__ == "__main__":
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    create_restrictive_file("secret.txt", content)
    create_restrictive_file("secret1.txt", content)
    create_restrictive_file("secret2.txt", content)
    create_restrictive_file("secret3.txt", content)
    create_restrictive_file("secret4.txt", content)