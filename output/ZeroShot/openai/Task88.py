import os
import tempfile
import secrets
import string

ALPHABET = string.ascii_letters + string.digits + "_-"

def create_temp_unicode_file(length: int) -> str:
    if length <= 0:
        raise ValueError("length must be > 0")

    # Generate a secure random string
    s = ''.join(secrets.choice(ALPHABET) for _ in range(length))

    # Convert to Unicode escape sequence representation
    unicode_escaped = ''.join('\\u%04X' % ord(ch) for ch in s)

    # Create a secure temporary file with 0600 permissions on POSIX
    fd, path = tempfile.mkstemp(prefix="task88_", suffix=".txt")
    try:
        with os.fdopen(fd, mode='w', encoding='utf-8', newline='\n') as f:
            f.write(unicode_escaped)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Ensure file descriptor is closed if an exception occurs before os.fdopen manages it
        try:
            os.close(fd)
        except Exception:
            pass
        raise
    return os.path.abspath(path)

if __name__ == "__main__":
    # 5 test cases
    print(create_temp_unicode_file(8))
    print(create_temp_unicode_file(12))
    print(create_temp_unicode_file(1))
    print(create_temp_unicode_file(32))
    print(create_temp_unicode_file(64))