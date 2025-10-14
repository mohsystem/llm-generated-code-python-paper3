import os
import tempfile

MAX_PASSWORD_LENGTH = 1024

def compare_password_from_file(file_path: str, user_password: str) -> bool:
    if file_path is None or user_password is None:
        return False
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            line = f.readline(MAX_PASSWORD_LENGTH + 2)
            if line is None:
                stored = ""
            else:
                # strip only one trailing newline and potential carriage return
                if line.endswith('\n'):
                    line = line[:-1]
                if line.endswith('\r'):
                    line = line[:-1]
                stored = line
            if len(stored) > MAX_PASSWORD_LENGTH:
                return False
    except (OSError, UnicodeError):
        return False

    # Constant-time, sequential compare
    len_a = len(stored)
    len_b = len(user_password)
    max_len = max(len_a, len_b)
    diff = len_a ^ len_b
    for i in range(max_len):
        ca = ord(stored[i]) if i < len_a else 0
        cb = ord(user_password[i]) if i < len_b else 0
        diff |= (ca ^ cb)
    return diff == 0

def _create_secure_temp_file(content: str) -> str:
    tf = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='', delete=False)
    try:
        os.chmod(tf.name, 0o600)
    except Exception:
        pass
    try:
        tf.write(content)
        tf.flush()
        return tf.name
    finally:
        tf.close()

if __name__ == "__main__":
    # Create 5 test files
    f1 = _create_secure_temp_file("secret123")
    f2 = _create_secure_temp_file("secret123")
    f3 = _create_secure_temp_file("pass with spaces")
    f4 = _create_secure_temp_file("")
    f5 = _create_secure_temp_file("short")

    try:
        print(compare_password_from_file(f1, "secret123"))  # True
        print(compare_password_from_file(f2, "secret124"))  # False
        print(compare_password_from_file(f3, "pass with spaces"))  # True
        print(compare_password_from_file(f4, ""))  # True
        print(compare_password_from_file(f5, "shorter"))  # False
    finally:
        for p in (f1, f2, f3, f4, f5):
            try:
                os.unlink(p)
            except Exception:
                pass