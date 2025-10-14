import secrets
import threading

_ISSUED = set()
_LOCK = threading.Lock()

def _clamp_length(num_bytes: int) -> int:
    try:
        n = int(num_bytes)
    except Exception:
        n = 32
    if n < 16 or n > 64:
        n = 32
    return n

def generate_session_id(num_bytes: int) -> str:
    n = _clamp_length(num_bytes)
    while True:
        token = secrets.token_bytes(n).hex()
        with _LOCK:
            if token not in _ISSUED:
                _ISSUED.add(token)
                return token
        # Extremely unlikely collision; regenerate

if __name__ == "__main__":
    # 5 test cases
    print(generate_session_id(32))
    print(generate_session_id(32))
    print(generate_session_id(32))
    print(generate_session_id(32))
    print(generate_session_id(32))