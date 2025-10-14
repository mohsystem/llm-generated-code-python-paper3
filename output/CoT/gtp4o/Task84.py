# Step 1-5: Secure session ID generator in Python
import base64
import secrets
import threading

_MIN_BYTES = 16
_MAX_BYTES = 1024
_MAX_ATTEMPTS = 1000
_issued_ids = set()
_lock = threading.Lock()

def generate_session_id(num_bytes: int) -> str:
    if not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be an integer")
    if num_bytes < _MIN_BYTES or num_bytes > _MAX_BYTES:
        raise ValueError(f"num_bytes must be between {_MIN_BYTES} and {_MAX_BYTES}")
    for _ in range(_MAX_ATTEMPTS):
        raw = secrets.token_bytes(num_bytes)
        sid = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
        with _lock:
            if sid not in _issued_ids:
                _issued_ids.add(sid)
                return sid
    raise RuntimeError(f"Unable to generate a unique session ID after {_MAX_ATTEMPTS} attempts")

if __name__ == "__main__":
    # 5 test cases
    print(generate_session_id(16))
    print(generate_session_id(24))
    print(generate_session_id(32))
    print(generate_session_id(48))
    print(generate_session_id(64))