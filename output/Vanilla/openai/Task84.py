import secrets
import string

_ALPHABET = string.ascii_letters + string.digits + "-_"
_ISSUED = set()

def generate_session_id(length: int) -> str:
    if length <= 0:
        raise ValueError("length must be > 0")
    while True:
        sid = ''.join(secrets.choice(_ALPHABET) for _ in range(length))
        if sid not in _ISSUED:
            _ISSUED.add(sid)
            return sid

if __name__ == "__main__":
    for length in [16, 24, 32, 40, 48]:
        print(generate_session_id(length))