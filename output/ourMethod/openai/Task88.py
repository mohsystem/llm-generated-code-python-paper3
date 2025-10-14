import os
import tempfile
from typing import List
import secrets

# Ranges: digits, uppercase, lowercase, Latin-1 supplement, Cyrillic, Emoji
RANGES: List[tuple[int, int]] = [
    (0x0030, 0x0039), (0x0041, 0x005A), (0x0061, 0x007A),
    (0x00C0, 0x00FF), (0x0400, 0x04FF), (0x1F600, 0x1F64F),
]

def _random_codepoint() -> int:
    r = RANGES[secrets.randbelow(len(RANGES))]
    lo, hi = r
    return lo + secrets.randbelow(hi - lo + 1)

def _generate_random_unicode_string(length: int) -> str:
    out = []
    attempts = 0
    max_attempts = length * 50
    while len(out) < length and attempts < max_attempts:
        attempts += 1
        cp = _random_codepoint()
        if 0xD800 <= cp <= 0xDFFF:
            continue  # skip surrogate range
        ch = chr(cp)
        try:
            ch.encode("utf-8")
        except Exception:
            continue
        out.append(ch)
    if len(out) < length:
        raise RuntimeError("Failed to generate sufficient random Unicode characters")
    return "".join(out)

def _to_codepoints_line(s: str) -> str:
    parts = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            parts.append(f"U+{cp:04X}")
        else:
            parts.append(f"U+{cp:06X}")
    return " ".join(parts)

def create_temp_unicode_file(length: int) -> str:
    if not isinstance(length, int) or length < 1 or length > 1024:
        raise ValueError("length must be an int in [1, 1024]")
    original = _generate_random_unicode_string(length)
    codepoints = _to_codepoints_line(original)

    # Create a secure temporary file and write UTF-8 content
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as f:
        # Set restrictive permissions (0600) where supported
        try:
            os.chmod(f.name, 0o600)
        except Exception:
            pass
        f.write("Original: ")
        f.write(original)
        f.write("\n")
        f.write("Codepoints: ")
        f.write(codepoints)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
        path = f.name
    return os.path.abspath(path)

if __name__ == "__main__":
    for t in [8, 16, 1, 32, 50]:
        try:
            p = create_temp_unicode_file(t)
            print(f"Created file (length {t}): {p}")
        except Exception as ex:
            print(f"Error for length {t}: {ex}")