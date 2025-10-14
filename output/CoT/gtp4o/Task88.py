# Chain-of-Through in code (comments only):
# 1) Problem: Create temp file (UTF-8), generate random string, convert to Unicode code point notation, write, return path.
# 2) Security: Use secrets for randomness, safe temp file creation, restrictive permissions when possible.
# 3) Implementation: Validate input, write with UTF-8 encoding, handle cross-platform permission nuances.
# 4) Review: Avoid race by using NamedTemporaryFile(delete=False), close before returning, ensure file descriptor closed.
# 5) Secure output: Final function returns the path; main runs 5 test cases.

import os
import tempfile
from secrets import SystemRandom
from typing import List

# Predefined Unicode code points
_CODE_POINTS: List[int] = (
    list(range(ord('A'), ord('Z') + 1)) +
    list(range(ord('a'), ord('z') + 1)) +
    list(range(ord('0'), ord('9') + 1)) +
    [
        0x00E9,  # é
        0x03A9,  # Ω
        0x0416,  # Ж
        0x4F60,  # 你
        0x597D,  # 好
        0x6F22,  # 漢
        0x20AC,  # €
        0x2603,  # ☃
        0x1F642, # 🙂
        0x1F680, # 🚀
        0x1F9E9, # 🧩
        0x1D6D1, # 𝛑
    ]
)

_rng = SystemRandom()

def _sanitize_length(length: int) -> int:
    if length is None or length < 0:
        return 16
    return min(length, 4096)

def _random_string(length: int) -> str:
    cps = [_rng.choice(_CODE_POINTS) for _ in range(length)]
    return ''.join(chr(cp) for cp in cps)

def _to_unicode_points(s: str) -> str:
    parts = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            parts.append(f"U+{cp:04X}")
        else:
            parts.append(f"U+{cp:06X}")
    return ' '.join(parts)

def create_temp_unicode_file(length: int) -> str:
    safe_len = _sanitize_length(length)
    rand_str = _random_string(safe_len)
    unicode_repr = _to_unicode_points(rand_str)

    # Create a secure temporary file; delete=False to keep and return path
    fd, path = tempfile.mkstemp(prefix="task88_", suffix=".txt")
    try:
        # Restrict permissions on POSIX (0600)
        try:
            os.fchmod(fd, 0o600)
        except AttributeError:
            pass  # Not available on some platforms
        with os.fdopen(fd, mode='w', encoding='utf-8', newline='') as f:
            f.write(unicode_repr)
    except Exception:
        # On exception, ensure file descriptor is closed and file is removed to avoid leakage
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.unlink(path)
        except Exception:
            pass
        raise
    return path

if __name__ == "__main__":
    tests = [0, 1, 5, 10, 50]
    for t in tests:
        try:
            p = create_temp_unicode_file(t)
            print(f"Created temp file (len={t}): {p}")
        except Exception as e:
            print(f"Failed for len={t}: {e}")